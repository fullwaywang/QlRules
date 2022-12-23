/**
 * @name linux-f9dbdf97a5bd92b1a49cee3d591b55b11fd7a6d5-iscsi_if_recv_msg
 * @id cpp/linux/f9dbdf97a5bd92b1a49cee3d591b55b11fd7a6d5/iscsi_if_recv_msg
 * @description linux-f9dbdf97a5bd92b1a49cee3d591b55b11fd7a6d5-iscsi_if_recv_msg 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Function func) {
	exists(DeclStmt target_0 |
		target_0.getDeclarationEntry(0).(VariableDeclarationEntry).getType() instanceof CTypedefType
		and func.getEntryPoint().(BlockStmt).getStmt(2)=target_0)
}

predicate func_1(Parameter vnlh_3623, Variable vev_3627) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(AssignExpr).getLValue().(VariableAccess).getType().hasName("u32")
		and target_1.getExpr().(AssignExpr).getRValue().(SubExpr).getLeftOperand().(SubExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="nlmsg_len"
		and target_1.getExpr().(AssignExpr).getRValue().(SubExpr).getLeftOperand().(SubExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vnlh_3623
		and target_1.getExpr().(AssignExpr).getRValue().(SubExpr).getLeftOperand().(SubExpr).getRightOperand().(SizeofExprOperator).getExprOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vnlh_3623
		and target_1.getExpr().(AssignExpr).getRValue().(SubExpr).getRightOperand().(SizeofExprOperator).getValue()="56"
		and target_1.getExpr().(AssignExpr).getRValue().(SubExpr).getRightOperand().(SizeofExprOperator).getExprOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vev_3627)
}

predicate func_2(Variable verr_3625, Variable vev_3627) {
	exists(IfStmt target_2 |
		target_2.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(ValueFieldAccess).getTarget().getName()="hdr_size"
		and target_2.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="send_pdu"
		and target_2.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="u"
		and target_2.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vev_3627
		and target_2.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getType().hasName("u32")
		and target_2.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(ValueFieldAccess).getTarget().getName()="data_size"
		and target_2.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="send_pdu"
		and target_2.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="u"
		and target_2.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vev_3627
		and target_2.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(SubExpr).getLeftOperand().(VariableAccess).getType().hasName("u32")
		and target_2.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(SubExpr).getRightOperand().(ValueFieldAccess).getTarget().getName()="hdr_size"
		and target_2.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(SubExpr).getRightOperand().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="send_pdu"
		and target_2.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(SubExpr).getRightOperand().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="u"
		and target_2.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(SubExpr).getRightOperand().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vev_3627
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=verr_3625
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(UnaryMinusExpr).getOperand().(Literal).getValue()="22"
		and target_2.getThen().(BlockStmt).getStmt(1) instanceof BreakStmt)
}

predicate func_5(Function func) {
	exists(BreakStmt target_5 |
		target_5.toString() = "break;"
		and target_5.getEnclosingFunction() = func)
}

predicate func_6(Parameter vnlh_3623) {
	exists(PointerFieldAccess target_6 |
		target_6.getTarget().getName()="nlmsg_type"
		and target_6.getQualifier().(VariableAccess).getTarget()=vnlh_3623)
}

predicate func_7(Variable vev_3627) {
	exists(PointerFieldAccess target_7 |
		target_7.getTarget().getName()="u"
		and target_7.getQualifier().(VariableAccess).getTarget()=vev_3627)
}

from Function func, Parameter vnlh_3623, Variable verr_3625, Variable vev_3627
where
not func_0(func)
and not func_1(vnlh_3623, vev_3627)
and not func_2(verr_3625, vev_3627)
and func_5(func)
and vnlh_3623.getType().hasName("nlmsghdr *")
and func_6(vnlh_3623)
and verr_3625.getType().hasName("int")
and vev_3627.getType().hasName("iscsi_uevent *")
and func_7(vev_3627)
and vnlh_3623.getParentScope+() = func
and verr_3625.getParentScope+() = func
and vev_3627.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
