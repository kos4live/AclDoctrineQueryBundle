<?php
/**
 * Based on mailaneel's ACLHelper
 *
 * @see https://gist.github.com/mailaneel/1363377
 * @see https://gist.github.com/gimler/5116843
 *
 * @author mailaneel
 * @author gimler
 * @author kos4live <git-acldoctrinequery@mail.go2inter.net>
 */

namespace kos4live\AclDoctrineQueryBundle\Helper;

use Doctrine\Bundle\DoctrineBundle\Registry;
use Doctrine\DBAL\Connection;
use Doctrine\ORM\Query;
use Doctrine\ORM\QueryBuilder;
use Doctrine\ORM\Mapping\QuoteStrategy;
use Symfony\Bridge\Doctrine\RegistryInterface;
use Symfony\Component\Security\Core\SecurityContextInterface;
use Symfony\Component\Security\Acl\Permission\MaskBuilder;
use Symfony\Component\Security\Core\User\UserInterface;

/**
 * Class AclQuery
 */
class AclQuery
{
    /**
     * @var string
     */
    private $aclWalkerClass;

    /**
     * @var Registry
     */
    private $doctrine;

    /**
     * @var SecurityContextInterface
     */
    private $securityContext;

    /**
     * @var Connection
     */
    private $aclConnection;

    /**
     * Constructor
     *
     * @param string                   $aclWalkerClass  AclWalker class
     * @param RegistryInterface        $doctrine        Doctrine
     * @param Connection               $connection      Connection
     * @param SecurityContextInterface $securityContext SecurityContext
     *
     * @return AclQuery
     */
    public function __construct($aclWalkerClass, RegistryInterface $doctrine, Connection $connection,
                                SecurityContextInterface $securityContext)
    {
        $this->aclWalkerClass = $aclWalkerClass;
        $this->doctrine = $doctrine;
        $this->securityContext = $securityContext;
        $this->aclConnection = $connection;
    }

    /**
     * Get Doctrine EntityManager
     *
     * @return \Doctrine\ORM\EntityManager
     */
    private function getEntityManager()
    {
        return $this->doctrine->getManager();
    }

    /**
     * Clone Query
     *
     * @param Query $query Query
     *
     * @return Query
     */
    protected function cloneQuery(Query $query)
    {
        $aclAppliedQuery = clone $query;
        $aclAppliedQuery->setParameters($query->getParameters());

        return $aclAppliedQuery;
    }

    /**
     * This will clone the original query and apply acl
     *
     * @param QueryBuilder  $queryBuilder Builder
     * @param array         $permissions  Permission mask
     * @param UserInterface $user         User
     *
     * @return Query
     */
    public function apply(QueryBuilder $queryBuilder, array $permissions = array("VIEW"), UserInterface $user = null)
    {

        $whereQueryParts = $queryBuilder->getDQLPart('where');
        if (empty($whereQueryParts)) {
            $fromQueryParts = $queryBuilder->getDQLPart('from');
            $firstFromQueryAlias = $fromQueryParts[0]->getAlias();
            // this will help in cases where no where query is specified,
            // where query is required to walk in where clause
            $queryBuilder->where($firstFromQueryAlias . '.id IS NOT NULL');
        }

        $query = $this->cloneQuery($queryBuilder->getQuery());


        $builder = new MaskBuilder();
        foreach ($permissions as $permission) {
            $mask = constant(get_class($builder) . '::MASK_' . strtoupper($permission));
            $builder->add($mask);
        }
        $query->setHint('acl.mask', $builder->get());

        $query->setHint(Query::HINT_CUSTOM_OUTPUT_WALKER, $this->aclWalkerClass);
        $entities = $queryBuilder->getRootEntities();
        $query->setHint('acl.root.entities', $entities);

        $query->setHint('acl.extra.query', $this->getPermittedIdsACLSQLForUser($query, $queryBuilder, $user));

        //$class = $this->getEntityManager()->getClassMetadata($entities[0]);
        //$entityRootTableName = $class->getQuotedTableName($this->getEntityManager()->getConnection()->getDatabasePlatform());
        /** @var QuoteStrategy $quoteStrategy */
        $quoteStrategy = $this->getEntityManager()->getConfiguration()->getQuoteStrategy();
        $entityRootTableName = $quoteStrategy->getTableName(
            $this->getEntityManager()->getClassMetadata($entities[0]),
            $this->getEntityManager()->getConnection()->getDatabasePlatform()
        );
        $entityRootAliases = $queryBuilder->getRootAliases();
        $entityRootAlias = $entityRootAliases[0];

        $query->setHint('acl.entityRootTableName', $entityRootTableName);
        $query->setHint('acl.entityRootTableDqlAlias', $entityRootAlias);

        return $query;
    }

    /**
     * This query works well with small offset, but if want to use it with large offsets please refer to the link on how to implement
     * http://www.scribd.com/doc/14683263/Efficient-Pagination-Using-MySQL
     * This will only check permissions on first enity added in the from clause, it will not check permissions
     * By default the number of rows returned are 10 starting from 0
     *
     * @param Query         $query        Query
     * @param QueryBuilder  $queryBuilder QueryBuilder
     * @param UserInterface $user         User
     *
     * @return string
     */
    private function getPermittedIdsACLSQLForUser(Query $query, QueryBuilder $queryBuilder, UserInterface $user = null)
    {
        $database = $this->aclConnection->getDatabase();
        $mask = $query->getHint('acl.mask');
        $rootEntities = $query->getHint('acl.root.entities');
        foreach ($rootEntities as $rootEntity) {
            $rE[] = '"' . str_replace('\\', '\\\\', $rootEntity) . '"';
            // For now ACL will be checked for first root entity, it will not check for all other entities in join etc..,
            break;
        }
        $rootEntities = implode(',', $rE);

        if (!is_object($user)) {
            $token = $this->securityContext->getToken(); // for now lets imagine we will have token i.e user is logged in
            $user = $token->getUser();
        }
        $identifier = "''";

        if (is_object($user)) {
            $identifiers = array();
            $userRoles = $user->getRoles();
            foreach ($userRoles as $role) {
                // The reason we ignore this is because by default FOSUserBundle adds ROLE_USER for every user
                if ($role !== 'ROLE_USER') {
                    $identifiers[] = $role;
                }
            }
            $identifiers[] = str_replace('\\', '\\\\', get_class($user)) . '-' . $user->getUserName();
            $identifier = '"' . implode('","', $identifiers) . '"';
        }

        $isNullExpression = $this->aclConnection->getDatabasePlatform()->getIsNullExpression('e.object_identity_id');
        $selectQuery = <<<SELECTQUERY
            SELECT DISTINCT o.object_identifier as id FROM {$database}.acl_object_identities as o
            INNER JOIN {$database}.acl_classes c ON c.id = o.class_id
            LEFT JOIN {$database}.acl_entries e ON (
                e.class_id = o.class_id AND (e.object_identity_id = o.id OR {$isNullExpression})
            )
            LEFT JOIN {$database}.acl_security_identities s ON (
                s.id = e.security_identity_id
            )
            WHERE c.class_type = {$rootEntities}
            AND s.identifier IN ({$identifier})
            AND e.mask >= {$mask}

SELECTQUERY;

        return $selectQuery;
    }
}
