/**
 * @name ffmpeg-2d453188c2303da641dafb048dc1806790526dfd-mov_read_uuid
 * @id cpp/ffmpeg/2d453188c2303da641dafb048dc1806790526dfd/mov-read-uuid
 * @description ffmpeg-2d453188c2303da641dafb048dc1806790526dfd-libavformat/mov.c-mov_read_uuid CVE-2017-5024
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vatom_4773, ReturnStmt target_3) {
	exists(RelationalOperation target_0 |
		 (target_0 instanceof GEExpr or target_0 instanceof LEExpr)
		and target_0.getGreaterOperand() instanceof ValueFieldAccess
		and target_0.getLesserOperand().(ConditionalExpr).getValue()="2147483647"
		and target_0.getParent().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(ValueFieldAccess).getTarget().getName()="size"
		and target_0.getParent().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vatom_4773
		and target_0.getParent().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(SizeofExprOperator).getValue()="16"
		and target_0.getParent().(LogicalOrExpr).getAnOperand() instanceof EqualityOperation
		and target_0.getParent().(LogicalOrExpr).getParent().(IfStmt).getThen()=target_3)
}

predicate func_1(Parameter vatom_4773, ValueFieldAccess target_1) {
		target_1.getTarget().getName()="size"
		and target_1.getQualifier().(VariableAccess).getTarget()=vatom_4773
}

predicate func_2(Parameter vatom_4773, ReturnStmt target_3, EqualityOperation target_2) {
		target_2.getAnOperand() instanceof ValueFieldAccess
		and target_2.getAnOperand().(Literal).getValue()="9223372036854775807"
		and target_2.getParent().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(ValueFieldAccess).getTarget().getName()="size"
		and target_2.getParent().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vatom_4773
		and target_2.getParent().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(SizeofExprOperator).getValue()="16"
		and target_2.getParent().(LogicalOrExpr).getParent().(IfStmt).getThen()=target_3
}

predicate func_3(ReturnStmt target_3) {
		target_3.getExpr().(UnaryMinusExpr).getValue()="-1094995529"
}

from Function func, Parameter vatom_4773, ValueFieldAccess target_1, EqualityOperation target_2, ReturnStmt target_3
where
not func_0(vatom_4773, target_3)
and func_1(vatom_4773, target_1)
and func_2(vatom_4773, target_3, target_2)
and func_3(target_3)
and vatom_4773.getType().hasName("MOVAtom")
and vatom_4773.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
