/**
 * @name libarchive-c0c52e9aaafb0860c4151c5374372051e9354301-get_time_t_max
 * @id cpp/libarchive/c0c52e9aaafb0860c4151c5374372051e9354301/get-time-t-max
 * @description libarchive-c0c52e9aaafb0860c4151c5374372051e9354301-libarchive/archive_read_support_format_mtree.c-get_time_t_max CVE-2015-8931
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

predicate func_1(RelationalOperation target_6, Function func) {
	exists(IfStmt target_1 |
		target_1.getCondition().(EqualityOperation).getValue()="1"
		and target_1.getThen().(BlockStmt).getStmt(0).(ReturnStmt).getExpr().(Literal).getValue()="9223372036854775807"
		and target_1.getElse().(BlockStmt).getStmt(0).(ReturnStmt).getExpr().(Literal).getValue()="2147483647"
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getElse().(BlockStmt).getStmt(0)=target_1
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_6
		and target_1.getEnclosingFunction() = func)
}

predicate func_3(RelationalOperation target_6, Function func, DeclStmt target_3) {
		target_3.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_6
		and target_3.getEnclosingFunction() = func
}

predicate func_4(RelationalOperation target_6, Function func, DeclStmt target_4) {
		target_4.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_6
		and target_4.getEnclosingFunction() = func
}

predicate func_5(Variable vmax_signed_time_t_152, VariableAccess target_5) {
		target_5.getTarget()=vmax_signed_time_t_152
}

predicate func_6(RelationalOperation target_6) {
		 (target_6 instanceof GTExpr or target_6 instanceof LTExpr)
		and target_6.getValue()="0"
}

from Function func, Variable vmax_signed_time_t_152, Literal target_0, DeclStmt target_3, DeclStmt target_4, VariableAccess target_5, RelationalOperation target_6
where
func_0(func, target_0)
and not func_1(target_6, func)
and func_3(target_6, func, target_3)
and func_4(target_6, func, target_4)
and func_5(vmax_signed_time_t_152, target_5)
and func_6(target_6)
and vmax_signed_time_t_152.getType().hasName("const uintmax_t")
and vmax_signed_time_t_152.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
