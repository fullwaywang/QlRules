/**
 * @name libyang-99b5b2a6c0edb9cddbe619b93f2bbd231a828aee-lys_compile
 * @id cpp/libyang/99b5b2a6c0edb9cddbe619b93f2bbd231a828aee/lys-compile
 * @description libyang-99b5b2a6c0edb9cddbe619b93f2bbd231a828aee-src/tree_schema_compile.c-lys_compile CVE-2019-20395
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vctx_5777, AddressOfExpr target_2, ValueFieldAccess target_3, Function func) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(FunctionCall).getTarget().hasName("ly_set_erase")
		and target_0.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(ValueFieldAccess).getTarget().getName()="tpdf_chain"
		and target_0.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vctx_5777
		and target_0.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="0"
		and (func.getEntryPoint().(BlockStmt).getStmt(51)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(51).getFollowingStmt()=target_0)
		and target_2.getOperand().(ValueFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(ValueFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(ValueFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_3.getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Variable vctx_5777, AddressOfExpr target_4, ValueFieldAccess target_5, Function func) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(FunctionCall).getTarget().hasName("ly_set_erase")
		and target_1.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(ValueFieldAccess).getTarget().getName()="tpdf_chain"
		and target_1.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vctx_5777
		and target_1.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="0"
		and (func.getEntryPoint().(BlockStmt).getStmt(62)=target_1 or func.getEntryPoint().(BlockStmt).getStmt(62).getFollowingStmt()=target_1)
		and target_4.getOperand().(ValueFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_1.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(ValueFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_1.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(ValueFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_5.getQualifier().(VariableAccess).getLocation()))
}

predicate func_2(Variable vctx_5777, AddressOfExpr target_2) {
		target_2.getOperand().(ValueFieldAccess).getTarget().getName()="groupings"
		and target_2.getOperand().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vctx_5777
}

predicate func_3(Variable vctx_5777, ValueFieldAccess target_3) {
		target_3.getTarget().getName()="ctx"
		and target_3.getQualifier().(VariableAccess).getTarget()=vctx_5777
}

predicate func_4(Variable vctx_5777, AddressOfExpr target_4) {
		target_4.getOperand().(ValueFieldAccess).getTarget().getName()="groupings"
		and target_4.getOperand().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vctx_5777
}

predicate func_5(Variable vctx_5777, ValueFieldAccess target_5) {
		target_5.getTarget().getName()="ctx"
		and target_5.getQualifier().(VariableAccess).getTarget()=vctx_5777
}

from Function func, Variable vctx_5777, AddressOfExpr target_2, ValueFieldAccess target_3, AddressOfExpr target_4, ValueFieldAccess target_5
where
not func_0(vctx_5777, target_2, target_3, func)
and not func_1(vctx_5777, target_4, target_5, func)
and func_2(vctx_5777, target_2)
and func_3(vctx_5777, target_3)
and func_4(vctx_5777, target_4)
and func_5(vctx_5777, target_5)
and vctx_5777.getType().hasName("lysc_ctx")
and vctx_5777.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
