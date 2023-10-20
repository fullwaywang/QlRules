/**
 * @name php-a5a15965da23c8e97657278fc8dfbf1dfb20c016-spl_filesystem_object_construct
 * @id cpp/php/a5a15965da23c8e97657278fc8dfbf1dfb20c016/spl-filesystem-object-construct
 * @description php-a5a15965da23c8e97657278fc8dfbf1dfb20c016-ext/spl/spl_directory.c-spl_filesystem_object_construct CVE-2019-11045
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func, StringLiteral target_0) {
		target_0.getValue()="s|l"
		and not target_0.getValue()="p|l"
		and target_0.getEnclosingFunction() = func
}

predicate func_1(Function func, StringLiteral target_1) {
		target_1.getValue()="s"
		and not target_1.getValue()="p"
		and target_1.getEnclosingFunction() = func
}

from Function func, StringLiteral target_0, StringLiteral target_1
where
func_0(func, target_0)
and func_1(func, target_1)
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
