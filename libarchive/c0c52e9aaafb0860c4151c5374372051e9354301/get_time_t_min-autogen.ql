/**
 * @name libarchive-c0c52e9aaafb0860c4151c5374372051e9354301-get_time_t_min
 * @id cpp/libarchive/c0c52e9aaafb0860c4151c5374372051e9354301/get-time-t-min
 * @description libarchive-c0c52e9aaafb0860c4151c5374372051e9354301-libarchive/archive_read_support_format_mtree.c-get_time_t_min CVE-2015-8931
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func, Literal target_0) {
		target_0.getValue()="0"
		and not target_0.getValue()="2147483647"
		and target_0.getParent().(ComplementExpr).getParent().(Initializer).getExpr() instanceof ComplementExpr
		and target_0.getEnclosingFunction() = func
}

predicate func_1(RelationalOperation target_8, Function func) {
	exists(IfStmt target_1 |
		target_1.getCondition().(EqualityOperation).getValue()="1"
		and target_1.getThen().(BlockStmt).getStmt(0).(ReturnStmt).getExpr().(SubExpr).getValue()="-9223372036854775808"
		and target_1.getElse().(BlockStmt).getStmt(0).(ReturnStmt).getExpr().(SubExpr).getValue()="-2147483648"
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getElse().(BlockStmt).getStmt(0)=target_1
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_8
		and target_1.getEnclosingFunction() = func)
}

/*predicate func_2(Function func) {
	exists(SubExpr target_2 |
		target_2.getValue()="-9223372036854775808"
		and target_2.getEnclosingFunction() = func)
}

*/
predicate func_4(RelationalOperation target_8, Function func, DeclStmt target_4) {
		target_4.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_8
		and target_4.getEnclosingFunction() = func
}

predicate func_5(RelationalOperation target_8, Function func, DeclStmt target_5) {
		target_5.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_8
		and target_5.getEnclosingFunction() = func
}

predicate func_6(RelationalOperation target_8, Function func, DeclStmt target_6) {
		target_6.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_8
		and target_6.getEnclosingFunction() = func
}

predicate func_7(Variable vmin_signed_time_t_171, VariableAccess target_7) {
		target_7.getTarget()=vmin_signed_time_t_171
}

predicate func_8(RelationalOperation target_8) {
		 (target_8 instanceof GTExpr or target_8 instanceof LTExpr)
		and target_8.getValue()="0"
}

from Function func, Variable vmin_signed_time_t_171, Literal target_0, DeclStmt target_4, DeclStmt target_5, DeclStmt target_6, VariableAccess target_7, RelationalOperation target_8
where
func_0(func, target_0)
and not func_1(target_8, func)
and func_4(target_8, func, target_4)
and func_5(target_8, func, target_5)
and func_6(target_8, func, target_6)
and func_7(vmin_signed_time_t_171, target_7)
and func_8(target_8)
and vmin_signed_time_t_171.getType().hasName("const intmax_t")
and vmin_signed_time_t_171.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
