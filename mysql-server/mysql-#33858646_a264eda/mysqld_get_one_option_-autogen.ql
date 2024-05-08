/**
 * @name mysql-server-a264eda151daa06789103d81964a6c51037ccc6f-mysqld_get_one_option_
 * @id cpp/mysql-server/a264eda151daa06789103d81964a6c51037ccc6f/mysqldgetoneoption
 * @description mysql-server-a264eda151daa06789103d81964a6c51037ccc6f-sql/ssl_init_callback.cc-mysqld_get_one_option_ mysql-#33858646
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func, StringLiteral target_0) {
	target_0.getValue()="--admin-tls-version=invalid"
	and not target_0.getValue()="--admin-tls-version=''"
	and target_0.getEnclosingFunction() = func
}

predicate func_1(Function func, StringLiteral target_1) {
	target_1.getValue()="--tls-version=invalid"
	and not target_1.getValue()="--tls-version=''"
	and target_1.getEnclosingFunction() = func
}

from Function func, StringLiteral target_0, StringLiteral target_1
where
func_0(func, target_0)
and func_1(func, target_1)
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
