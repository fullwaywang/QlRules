/**
 * @name curl-8c7ee9083d0d71-post_per_transfer
 * @id cpp/curl/8c7ee9083d0d71/post-per-transfer
 * @description curl-8c7ee9083d0d71-post_per_transfer CVE-2022-27778
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func) {
	exists(StringLiteral target_0 |
		target_0.getValue()="Removing output file: %s"
		and not target_0.getValue()="Removing output file: %s\n"
		and target_0.getEnclosingFunction() = func)
}

predicate func_1(Parameter vper_332) {
	exists(PointerFieldAccess target_1 |
		target_1.getTarget().getName()="outfile"
		and target_1.getQualifier().(VariableAccess).getTarget()=vper_332)
}

predicate func_4(Parameter vglobal_331, Parameter vper_332) {
	exists(PointerFieldAccess target_4 |
		target_4.getTarget().getName()="outfile"
		and target_4.getQualifier().(VariableAccess).getTarget()=vper_332
		and target_4.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("notef")
		and target_4.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vglobal_331
		and target_4.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1) instanceof StringLiteral)
}

predicate func_5(Variable vouts_337) {
	exists(PointerFieldAccess target_5 |
		target_5.getTarget().getName()="stream"
		and target_5.getQualifier().(VariableAccess).getTarget()=vouts_337)
}

from Function func, Variable vouts_337, Parameter vglobal_331, Parameter vper_332
where
func_0(func)
and func_1(vper_332)
and func_4(vglobal_331, vper_332)
and vouts_337.getType().hasName("OutStruct *")
and func_5(vouts_337)
and vglobal_331.getType().hasName("GlobalConfig *")
and vper_332.getType().hasName("per_transfer *")
and vouts_337.getParentScope+() = func
and vglobal_331.getParentScope+() = func
and vper_332.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
