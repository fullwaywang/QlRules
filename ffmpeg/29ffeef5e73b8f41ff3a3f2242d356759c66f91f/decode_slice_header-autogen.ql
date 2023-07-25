/**
 * @name ffmpeg-29ffeef5e73b8f41ff3a3f2242d356759c66f91f-decode_slice_header
 * @id cpp/ffmpeg/29ffeef5e73b8f41ff3a3f2242d356759c66f91f/decode-slice-header
 * @description ffmpeg-29ffeef5e73b8f41ff3a3f2242d356759c66f91f-libavcodec/h264.c-decode_slice_header CVE-2013-7008
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vh0_3366, BlockStmt target_6, EqualityOperation target_0) {
		target_0.getAnOperand().(ValueFieldAccess).getTarget().getName()="owner"
		and target_0.getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="tf"
		and target_0.getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="cur_pic_ptr"
		and target_0.getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vh0_3366
		and target_0.getAnOperand().(PointerFieldAccess).getTarget().getName()="avctx"
		and target_0.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vh0_3366
		and target_0.getParent().(LogicalAndExpr).getAnOperand() instanceof NotExpr
		and target_0.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen()=target_6
}

predicate func_1(Variable vlast_pic_structure_3372, BlockStmt target_7, EqualityOperation target_1) {
		target_1.getAnOperand().(VariableAccess).getTarget()=vlast_pic_structure_3372
		and target_1.getAnOperand().(Literal).getValue()="3"
		and target_1.getParent().(LogicalAndExpr).getAnOperand() instanceof NotExpr
		and target_1.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen()=target_7
}

predicate func_2(Variable vlast_pic_structure_3372, BlockStmt target_8, EqualityOperation target_2) {
		target_2.getAnOperand().(VariableAccess).getTarget()=vlast_pic_structure_3372
		and target_2.getAnOperand().(Literal).getValue()="3"
		and target_2.getParent().(LogicalAndExpr).getAnOperand() instanceof NotExpr
		and target_2.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen()=target_8
}

predicate func_3(Variable vlast_pic_droppable_3372, LogicalAndExpr target_3) {
		target_3.getAnOperand().(NotExpr).getOperand().(VariableAccess).getTarget()=vlast_pic_droppable_3372
		and target_3.getAnOperand() instanceof EqualityOperation
		and target_3.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0) instanceof ExprStmt
}

predicate func_4(Variable vlast_pic_droppable_3372, LogicalAndExpr target_3, LogicalAndExpr target_5, LogicalAndExpr target_4) {
		target_4.getAnOperand().(NotExpr).getOperand().(VariableAccess).getTarget()=vlast_pic_droppable_3372
		and target_4.getAnOperand() instanceof EqualityOperation
		and target_4.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0) instanceof ExprStmt
		and target_3.getAnOperand().(NotExpr).getOperand().(VariableAccess).getLocation().isBefore(target_4.getAnOperand().(NotExpr).getOperand().(VariableAccess).getLocation())
		and target_4.getAnOperand().(NotExpr).getOperand().(VariableAccess).getLocation().isBefore(target_5.getAnOperand().(NotExpr).getOperand().(VariableAccess).getLocation())
}

predicate func_5(Variable vlast_pic_droppable_3372, LogicalAndExpr target_4, ExprStmt target_9, LogicalAndExpr target_5) {
		target_5.getAnOperand().(NotExpr).getOperand().(VariableAccess).getTarget()=vlast_pic_droppable_3372
		and target_5.getAnOperand() instanceof EqualityOperation
		and target_5.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0) instanceof ExprStmt
		and target_4.getAnOperand().(NotExpr).getOperand().(VariableAccess).getLocation().isBefore(target_5.getAnOperand().(NotExpr).getOperand().(VariableAccess).getLocation())
		and target_5.getAnOperand().(NotExpr).getOperand().(VariableAccess).getLocation().isBefore(target_9.getExpr().(AssignExpr).getRValue().(VariableAccess).getLocation())
}

predicate func_6(Parameter vh0_3366, Variable vlast_pic_structure_3372, BlockStmt target_6) {
		target_6.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ff_thread_report_progress")
		and target_6.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="tf"
		and target_6.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="cur_pic_ptr"
		and target_6.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vh0_3366
		and target_6.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="2147483647"
		and target_6.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vlast_pic_structure_3372
		and target_6.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(EqualityOperation).getAnOperand().(Literal).getValue()="2"
}

predicate func_7(Parameter vh0_3366, Variable vlast_pic_structure_3372, BlockStmt target_7) {
		target_7.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ff_thread_report_progress")
		and target_7.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="tf"
		and target_7.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="cur_pic_ptr"
		and target_7.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vh0_3366
		and target_7.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="2147483647"
		and target_7.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vlast_pic_structure_3372
		and target_7.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(EqualityOperation).getAnOperand().(Literal).getValue()="1"
}

predicate func_8(Parameter vh0_3366, Variable vlast_pic_structure_3372, BlockStmt target_8) {
		target_8.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ff_thread_report_progress")
		and target_8.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="tf"
		and target_8.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="cur_pic_ptr"
		and target_8.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vh0_3366
		and target_8.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="2147483647"
		and target_8.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vlast_pic_structure_3372
		and target_8.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(EqualityOperation).getAnOperand().(Literal).getValue()="1"
}

predicate func_9(Variable vlast_pic_droppable_3372, ExprStmt target_9) {
		target_9.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="droppable"
		and target_9.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("H264Context *")
		and target_9.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vlast_pic_droppable_3372
}

from Function func, Parameter vh0_3366, Variable vlast_pic_structure_3372, Variable vlast_pic_droppable_3372, EqualityOperation target_0, EqualityOperation target_1, EqualityOperation target_2, LogicalAndExpr target_3, LogicalAndExpr target_4, LogicalAndExpr target_5, BlockStmt target_6, BlockStmt target_7, BlockStmt target_8, ExprStmt target_9
where
func_0(vh0_3366, target_6, target_0)
and func_1(vlast_pic_structure_3372, target_7, target_1)
and func_2(vlast_pic_structure_3372, target_8, target_2)
and func_3(vlast_pic_droppable_3372, target_3)
and func_4(vlast_pic_droppable_3372, target_3, target_5, target_4)
and func_5(vlast_pic_droppable_3372, target_4, target_9, target_5)
and func_6(vh0_3366, vlast_pic_structure_3372, target_6)
and func_7(vh0_3366, vlast_pic_structure_3372, target_7)
and func_8(vh0_3366, vlast_pic_structure_3372, target_8)
and func_9(vlast_pic_droppable_3372, target_9)
and vh0_3366.getType().hasName("H264Context *")
and vlast_pic_structure_3372.getType().hasName("int")
and vlast_pic_droppable_3372.getType().hasName("int")
and vh0_3366.getFunction() = func
and vlast_pic_structure_3372.(LocalVariable).getFunction() = func
and vlast_pic_droppable_3372.(LocalVariable).getFunction() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
