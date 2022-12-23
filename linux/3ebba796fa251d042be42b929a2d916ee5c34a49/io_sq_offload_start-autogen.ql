/**
 * @name linux-3ebba796fa251d042be42b929a2d916ee5c34a49-io_sq_offload_start
 * @id cpp/linux/3ebba796fa251d042be42b929a2d916ee5c34a49/io-sq-offload-start
 * @description linux-3ebba796fa251d042be42b929a2d916ee5c34a49-io_sq_offload_start 
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vctx_7915, Function func) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(AssignAndExpr).getLValue().(ValueFieldAccess).getTarget().getName()="flags"
		and target_0.getExpr().(AssignAndExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="(unknown field)"
		and target_0.getExpr().(AssignAndExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctx_7915
		and target_0.getExpr().(AssignAndExpr).getRValue().(ComplementExpr).getValue()="4294967231"
		and target_0.getExpr().(AssignAndExpr).getRValue().(ComplementExpr).getOperand().(BinaryBitwiseOperation).getValue()="64"
		and target_0.getExpr().(AssignAndExpr).getRValue().(ComplementExpr).getOperand().(BinaryBitwiseOperation).getLeftOperand().(Literal).getValue()="1"
		and target_0.getExpr().(AssignAndExpr).getRValue().(ComplementExpr).getOperand().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="6"
		and (func.getEntryPoint().(BlockStmt).getStmt(1)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(1).getFollowingStmt()=target_0))
}

predicate func_1(Parameter vctx_7915) {
	exists(PointerFieldAccess target_1 |
		target_1.getTarget().getName()="sq_data"
		and target_1.getQualifier().(VariableAccess).getTarget()=vctx_7915)
}

from Function func, Parameter vctx_7915
where
not func_0(vctx_7915, func)
and vctx_7915.getType().hasName("io_ring_ctx *")
and func_1(vctx_7915)
and vctx_7915.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
