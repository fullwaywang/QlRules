/**
 * @name postgresql-582edc369cdbd348d68441fc50fa26a84afd0c1a-processSQLNamePattern
 * @id cpp/postgresql/582edc369cdbd348d68441fc50fa26a84afd0c1a/processSQLNamePattern
 * @description postgresql-582edc369cdbd348d68441fc50fa26a84afd0c1a-src/fe_utils/string_utils.c-processSQLNamePattern CVE-2018-1058
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func, StringLiteral target_0) {
		target_0.getValue()="(%s ~ "
		and not target_0.getValue()="(%s OPERATOR(pg_catalog.~) "
		and target_0.getEnclosingFunction() = func
}

predicate func_1(Function func, StringLiteral target_1) {
		target_1.getValue()="\n        OR %s ~ "
		and not target_1.getValue()="\n        OR %s OPERATOR(pg_catalog.~) "
		and target_1.getEnclosingFunction() = func
}

predicate func_2(Function func, StringLiteral target_2) {
		target_2.getValue()="%s ~ "
		and not target_2.getValue()="%s OPERATOR(pg_catalog.~) "
		and target_2.getEnclosingFunction() = func
}

predicate func_3(Function func, StringLiteral target_3) {
		target_3.getValue()="%s ~ "
		and not target_3.getValue()="%s OPERATOR(pg_catalog.~) "
		and target_3.getEnclosingFunction() = func
}

from Function func, StringLiteral target_0, StringLiteral target_1, StringLiteral target_2, StringLiteral target_3
where
func_0(func, target_0)
and func_1(func, target_1)
and func_2(func, target_2)
and func_3(func, target_3)
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
