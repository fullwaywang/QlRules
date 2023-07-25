/**
 * @name wireshark-bf9272a92f3df1e4ccfaad434e123222ae5313f7-register_p_mul_id
 * @id cpp/wireshark/bf9272a92f3df1e4ccfaad434e123222ae5313f7/register-p-mul-id
 * @description wireshark-bf9272a92f3df1e4ccfaad434e123222ae5313f7-epan/dissectors/packet-p_mul.c-register_p_mul_id CVE-2019-5717
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vpdu_type_354, Parameter vseq_no_355, LogicalAndExpr target_1, ExprStmt target_2, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vpdu_type_354
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vseq_no_355
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_0.getThen().(BlockStmt).getStmt(0).(ReturnStmt).getExpr().(Literal).getValue()="0"
		and (func.getEntryPoint().(BlockStmt).getStmt(9)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(9).getFollowingStmt()=target_0)
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getLocation().isBefore(target_1.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getLocation())
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getLocation().isBefore(target_2.getExpr().(AssignExpr).getRValue().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vpdu_type_354, LogicalAndExpr target_1) {
		target_1.getAnOperand().(NotExpr).getOperand().(ValueFieldAccess).getTarget().getName()="visited"
		and target_1.getAnOperand().(NotExpr).getOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="flags"
		and target_1.getAnOperand().(NotExpr).getOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="fd"
		and target_1.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vpdu_type_354
		and target_1.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="2"
		and target_1.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vpdu_type_354
		and target_1.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_1.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vpdu_type_354
		and target_1.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="3"
}

predicate func_2(Parameter vseq_no_355, ExprStmt target_2) {
		target_2.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="last_found_pdu"
		and target_2.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vseq_no_355
}

from Function func, Parameter vpdu_type_354, Parameter vseq_no_355, LogicalAndExpr target_1, ExprStmt target_2
where
not func_0(vpdu_type_354, vseq_no_355, target_1, target_2, func)
and func_1(vpdu_type_354, target_1)
and func_2(vseq_no_355, target_2)
and vpdu_type_354.getType().hasName("guint8")
and vseq_no_355.getType().hasName("guint16")
and vpdu_type_354.getParentScope+() = func
and vseq_no_355.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
