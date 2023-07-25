/**
 * @name wireshark-72ad7d9cdd4384857eec31d7ae295a330aa2d0ff-dissect_ippusb
 * @id cpp/wireshark/72ad7d9cdd4384857eec31d7ae295a330aa2d0ff/dissect-ippusb
 * @description wireshark-72ad7d9cdd4384857eec31d7ae295a330aa2d0ff-epan/dissectors/packet-ippusb.c-dissect_ippusb CVE-2021-39920
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vlast_chunk_204, Variable vcurrent_msp_209, BlockStmt target_2, NotExpr target_3, BitwiseAndExpr target_4, FunctionCall target_5) {
	exists(LogicalAndExpr target_0 |
		target_0.getAnOperand().(VariableAccess).getTarget()=vcurrent_msp_209
		and target_0.getAnOperand().(VariableAccess).getTarget()=vlast_chunk_204
		and target_0.getParent().(LogicalAndExpr).getAnOperand().(VariableAccess).getTarget()=vlast_chunk_204
		and target_0.getParent().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getTarget().hasName("strncmp")
		and target_0.getParent().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vlast_chunk_204
		and target_0.getParent().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(2).(Literal).getValue()="5"
		and target_0.getParent().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_0.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen()=target_2
		and target_3.getOperand().(LogicalAndExpr).getAnOperand().(VariableAccess).getLocation().isBefore(target_0.getAnOperand().(VariableAccess).getLocation())
		and target_4.getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getAnOperand().(VariableAccess).getLocation())
		and target_0.getAnOperand().(VariableAccess).getLocation().isBefore(target_5.getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Variable vlast_chunk_204, BlockStmt target_2, VariableAccess target_1) {
		target_1.getTarget()=vlast_chunk_204
		and target_1.getParent().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getTarget().hasName("strncmp")
		and target_1.getParent().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vlast_chunk_204
		and target_1.getParent().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(2).(Literal).getValue()="5"
		and target_1.getParent().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_1.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen()=target_2
}

predicate func_2(BlockStmt target_2) {
		target_2.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("proto_tree_add_item")
		and target_2.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(4).(UnaryMinusExpr).getValue()="-1"
		and target_2.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(5).(Literal).getValue()="0"
		and target_2.getStmt(3).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="can_desegment"
		and target_2.getStmt(3).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_2.getStmt(3).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("dissector_try_uint_new")
		and target_2.getStmt(3).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(Literal).getValue()="0"
		and target_2.getStmt(3).(IfStmt).getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("col_append_fstr")
		and target_2.getStmt(3).(IfStmt).getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="cinfo"
		and target_2.getStmt(3).(IfStmt).getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()=" Reassembled Data"
}

predicate func_3(Variable vlast_chunk_204, NotExpr target_3) {
		target_3.getOperand().(LogicalAndExpr).getAnOperand().(VariableAccess).getTarget()=vlast_chunk_204
		and target_3.getOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getTarget().hasName("strncmp")
		and target_3.getOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vlast_chunk_204
		and target_3.getOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(2).(Literal).getValue()="5"
		and target_3.getOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
}

predicate func_4(Variable vcurrent_msp_209, BitwiseAndExpr target_4) {
		target_4.getLeftOperand().(PointerFieldAccess).getTarget().getName()="document"
		and target_4.getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcurrent_msp_209
		and target_4.getRightOperand().(Literal).getValue()="2"
}

predicate func_5(Variable vcurrent_msp_209, FunctionCall target_5) {
		target_5.getTarget().hasName("fragment_get_reassembled_id")
		and target_5.getArgument(2).(PointerFieldAccess).getTarget().getName()="first_frame"
		and target_5.getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcurrent_msp_209
}

from Function func, Variable vlast_chunk_204, Variable vcurrent_msp_209, VariableAccess target_1, BlockStmt target_2, NotExpr target_3, BitwiseAndExpr target_4, FunctionCall target_5
where
not func_0(vlast_chunk_204, vcurrent_msp_209, target_2, target_3, target_4, target_5)
and func_1(vlast_chunk_204, target_2, target_1)
and func_2(target_2)
and func_3(vlast_chunk_204, target_3)
and func_4(vcurrent_msp_209, target_4)
and func_5(vcurrent_msp_209, target_5)
and vlast_chunk_204.getType().hasName("const guchar *")
and vcurrent_msp_209.getType().hasName("ippusb_multisegment_pdu *")
and vlast_chunk_204.getParentScope+() = func
and vcurrent_msp_209.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
