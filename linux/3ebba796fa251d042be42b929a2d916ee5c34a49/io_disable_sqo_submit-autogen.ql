/**
 * @name linux-3ebba796fa251d042be42b929a2d916ee5c34a49-io_disable_sqo_submit
 * @id cpp/linux/3ebba796fa251d042be42b929a2d916ee5c34a49/io-disable-sqo-submit
 * @description linux-3ebba796fa251d042be42b929a2d916ee5c34a49-io_disable_sqo_submit 
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vctx_8691, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(BitwiseAndExpr).getLeftOperand().(ValueFieldAccess).getTarget().getName()="flags"
		and target_0.getCondition().(BitwiseAndExpr).getLeftOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="(unknown field)"
		and target_0.getCondition().(BitwiseAndExpr).getLeftOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctx_8691
		and target_0.getCondition().(BitwiseAndExpr).getRightOperand().(BinaryBitwiseOperation).getValue()="64"
		and target_0.getCondition().(BitwiseAndExpr).getRightOperand().(BinaryBitwiseOperation).getLeftOperand().(Literal).getValue()="1"
		and target_0.getCondition().(BitwiseAndExpr).getRightOperand().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="6"
		and target_0.getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("io_sq_offload_start")
		and target_0.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vctx_8691
		and (func.getEntryPoint().(BlockStmt).getStmt(2)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(2).getFollowingStmt()=target_0))
}

predicate func_1(Parameter vctx_8691) {
	exists(PointerFieldAccess target_1 |
		target_1.getTarget().getName()="(unknown field)"
		and target_1.getQualifier().(VariableAccess).getTarget()=vctx_8691)
}

from Function func, Parameter vctx_8691
where
not func_0(vctx_8691, func)
and vctx_8691.getType().hasName("io_ring_ctx *")
and func_1(vctx_8691)
and vctx_8691.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
