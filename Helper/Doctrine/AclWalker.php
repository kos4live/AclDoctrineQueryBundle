<?php
/**
 * Based on mailaneel's ACLHelper
 *
 * @see https://gist.github.com/mailaneel/1363377
 *
 * @author mailaneel
 * @author kos4live <git-acldoctrinequery@mail.go2inter.net>
 */

namespace kos4live\AclDoctrineQueryBundle\Helper\Doctrine;

use Doctrine\ORM\Query\SqlWalker;
use Doctrine\ORM\Query;

/**
 * Class AclWalker
 */
class AclWalker extends SqlWalker
{
    /**
     * Walks down a FromClause AST node, thereby generating the appropriate SQL.
     *
     * @param string $fromClause fromClause
     *
     * @return string The SQL.
     */
    public function walkFromClause($fromClause)
    {
        $sql = parent::walkFromClause($fromClause);

        $tableAlias = $this->getSQLTableAlias(
            $this->getQuery()->getHint('acl.entityRootTableName'),
            $this->getQuery()->getHint('acl.entityRootTableDqlAlias')
        );
        $extraQuery = $this->getQuery()->getHint('acl.extra.query');

        $tempAclView = sprintf(' JOIN (%s) ta_ ON %s.id = ta_.id ', $extraQuery, $tableAlias);

        return $sql . $tempAclView;
    }
}