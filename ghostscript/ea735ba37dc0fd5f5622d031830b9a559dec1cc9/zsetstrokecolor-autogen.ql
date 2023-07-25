/**
 * @name ghostscript-ea735ba37dc0fd5f5622d031830b9a559dec1cc9-zsetstrokecolor
 * @id cpp/ghostscript/ea735ba37dc0fd5f5622d031830b9a559dec1cc9/zsetstrokecolor
 * @description ghostscript-ea735ba37dc0fd5f5622d031830b9a559dec1cc9-psi/zcolor.c-zsetstrokecolor CVE-2018-16510
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vi_ctx_p_6611, ExprStmt target_2, Function func) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="p"
		and target_0.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="stack"
		and target_0.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="exec_stack"
		and target_0.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vi_ctx_p_6611
		and target_0.getExpr().(AssignExpr).getRValue().(VariableAccess).getType().hasName("es_ptr")
		and (func.getEntryPoint().(BlockStmt).getStmt(9)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(9).getFollowingStmt()=target_0)
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_0.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vi_ctx_p_6611, Function func) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(FunctionCall).getTarget().hasName("zswapcolors")
		and target_1.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vi_ctx_p_6611
		and (func.getEntryPoint().(BlockStmt).getStmt(10)=target_1 or func.getEntryPoint().(BlockStmt).getStmt(10).getFollowingStmt()=target_1))
}

predicate func_2(Parameter vi_ctx_p_6611, ExprStmt target_2) {
		target_2.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("int")
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("zsetcolor")
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vi_ctx_p_6611
}

from Function func, Parameter vi_ctx_p_6611, ExprStmt target_2
where
not func_0(vi_ctx_p_6611, target_2, func)
and not func_1(vi_ctx_p_6611, func)
and func_2(vi_ctx_p_6611, target_2)
and vi_ctx_p_6611.getType().hasName("i_ctx_t *")
and vi_ctx_p_6611.getFunction() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
