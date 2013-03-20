AclDoctrineQueryBundle
======================

Helper Bundle for Symfony2 ACL

Usage:
------

    $aclQueryHelper = $this->get('kos4live.acl_doctrine_query.helper');
    $em = $this->getDoctrine()->getManager();
    $qb = $em->createQueryBuilder();

    $qb = $qb->select('p')
        ->from('Entity\Product', 'p');
    $qb->setMaxResults(10);

    $permissions = array('view');
    $user = $this->getUser();

    // The returned query object is a clone, you can alway use $qb->getQuery() to get the original query object
    $query = $aqlQueryHelper->apply($qb, $permissions, $user);

    $result = $query->getArrayResult();

The $user parameter of apply() is optional and if is not set or null, the securityContext would use to determine the current user.


Don't forget add to AppKernel.php
    new kos4live\AclDoctrineQueryBundle\kos4liveAclDoctrineQueryBundle(),
