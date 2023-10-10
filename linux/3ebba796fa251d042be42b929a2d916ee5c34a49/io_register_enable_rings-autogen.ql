/**
 * @name linux-3ebba796fa251d042be42b929a2d916ee5c34a49-io_register_enable_rings
 * @id cpp/linux/3ebba796fa251d042be42b929a2d916ee5c34a49/io-register-enable-rings
 * @description linux-3ebba796fa251d042be42b929a2d916ee5c34a49-io_register_enable_rings 
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vctx_9632, Function func) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(AssignAndExpr).getLValue().(ValueFieldAccess).getTarget().getName()="flags"
		and target_0.getExpr().(AssignAndExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="(unknown field)"
		and target_0.getExpr().(AssignAndExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctx_9632
		and target_0.getExpr().(AssignAndExpr).getRValue().(ComplementExpr).getValue()="4294967231"
		and target_0.getExpr().(AssignAndExpr).getRValue().(ComplementExpr).getOperand().(BinaryBitwiseOperation).getValue()="64"
		and target_0.getExpr().(AssignAndExpr).getRValue().(ComplementExpr).getOperand().(BinaryBitwiseOperation).getLeftOperand().(Literal).getValue()="1"
		and target_0.getExpr().(AssignAndExpr).getRValue().(ComplementExpr).getOperand().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="6"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_0)
}

from Function func, Parameter vctx_9632
where
func_0(vctx_9632, func)
and vctx_9632.getType().hasName("io_ring_ctx *")
and vctx_9632.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
