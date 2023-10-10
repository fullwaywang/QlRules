/**
 * @name openjpeg-7256e43c48ba5f7b1b8ee2927a52dc783a7ab3ed-opj_jp2_read_header_procedure
 * @id cpp/openjpeg/7256e43c48ba5f7b1b8ee2927a52dc783a7ab3ed/opj-jp2-read-header-procedure
 * @description openjpeg-7256e43c48ba5f7b1b8ee2927a52dc783a7ab3ed-src/lib/openjp2/jp2.c-opj_jp2_read_header_procedure CVE-2014-7945
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vstream_1803, Parameter vp_manager_1804, Variable vbox_1807, Variable vl_current_data_size_1811, EqualityOperation target_3, FunctionCall target_4, ExprStmt target_5, ExprStmt target_6, ExprStmt target_7, ExprStmt target_8, RelationalOperation target_9) {
	exists(IfStmt target_0 |
		target_0.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vl_current_data_size_1811
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(FunctionCall).getTarget().hasName("opj_stream_get_number_byte_left")
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vstream_1803
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("opj_event_msg")
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vp_manager_1804
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="1"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="Invalid box size %d for box '%c%c%c%c'. Need %d bytes, %d bytes remaining \n"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(ValueFieldAccess).getTarget().getName()="length"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vbox_1807
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(4).(BinaryBitwiseOperation).getLeftOperand().(ValueFieldAccess).getTarget().getName()="type"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(4).(BinaryBitwiseOperation).getLeftOperand().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vbox_1807
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(4).(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="24"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(5).(BinaryBitwiseOperation).getLeftOperand().(ValueFieldAccess).getTarget().getName()="type"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(5).(BinaryBitwiseOperation).getLeftOperand().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vbox_1807
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(5).(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="16"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(6).(BinaryBitwiseOperation).getLeftOperand().(ValueFieldAccess).getTarget().getName()="type"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(6).(BinaryBitwiseOperation).getLeftOperand().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vbox_1807
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(6).(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="8"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(7).(BinaryBitwiseOperation).getLeftOperand().(ValueFieldAccess).getTarget().getName()="type"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(7).(BinaryBitwiseOperation).getLeftOperand().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vbox_1807
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(7).(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="0"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(8).(VariableAccess).getTarget()=vl_current_data_size_1811
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(9).(FunctionCall).getTarget().hasName("opj_stream_get_number_byte_left")
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(9).(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vstream_1803
		and target_0.getThen().(BlockStmt).getStmt(1) instanceof ExprStmt
		and target_0.getThen().(BlockStmt).getStmt(2).(ReturnStmt).getExpr().(Literal).getValue()="0"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0)=target_0
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_3
		and target_4.getArgument(2).(VariableAccess).getLocation().isBefore(target_0.getCondition().(RelationalOperation).getLesserOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_6.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_7.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_8.getExpr().(AssignExpr).getRValue().(SubExpr).getLeftOperand().(ValueFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(ValueFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation().isBefore(target_9.getGreaterOperand().(VariableAccess).getLocation()))
}

predicate func_1(Variable vl_current_data_1812, ExprStmt target_10, ExprStmt target_2, Function func) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(FunctionCall).getTarget().hasName("free")
		and target_1.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vl_current_data_1812
		and (func.getEntryPoint().(BlockStmt).getStmt(12)=target_1 or func.getEntryPoint().(BlockStmt).getStmt(12).getFollowingStmt()=target_1)
		and target_10.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_1.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_1.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_2.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

predicate func_2(Variable vl_current_data_1812, Function func, ExprStmt target_2) {
		target_2.getExpr().(FunctionCall).getTarget().hasName("free")
		and target_2.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vl_current_data_1812
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_2
}

predicate func_3(EqualityOperation target_3) {
		target_3.getAnOperand().(OctalLiteral).getValue()="0"
}

predicate func_4(Parameter vstream_1803, Parameter vp_manager_1804, Variable vbox_1807, FunctionCall target_4) {
		target_4.getTarget().hasName("opj_jp2_read_boxhdr")
		and target_4.getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vbox_1807
		and target_4.getArgument(2).(VariableAccess).getTarget()=vstream_1803
		and target_4.getArgument(3).(VariableAccess).getTarget()=vp_manager_1804
}

predicate func_5(Parameter vstream_1803, Parameter vp_manager_1804, Variable vl_current_data_size_1811, Variable vl_current_data_1812, ExprStmt target_5) {
		target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("opj_stream_read_data")
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vstream_1803
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vl_current_data_1812
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vl_current_data_size_1811
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vp_manager_1804
}

predicate func_6(Parameter vp_manager_1804, Variable vbox_1807, ExprStmt target_6) {
		target_6.getExpr().(FunctionCall).getTarget().hasName("opj_event_msg")
		and target_6.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vp_manager_1804
		and target_6.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="1"
		and target_6.getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="invalid box size %d (%x)\n"
		and target_6.getExpr().(FunctionCall).getArgument(3).(ValueFieldAccess).getTarget().getName()="length"
		and target_6.getExpr().(FunctionCall).getArgument(3).(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vbox_1807
		and target_6.getExpr().(FunctionCall).getArgument(4).(ValueFieldAccess).getTarget().getName()="type"
		and target_6.getExpr().(FunctionCall).getArgument(4).(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vbox_1807
}

predicate func_7(Parameter vp_manager_1804, ExprStmt target_7) {
		target_7.getExpr().(FunctionCall).getTarget().hasName("opj_event_msg")
		and target_7.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vp_manager_1804
		and target_7.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="1"
		and target_7.getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="Not enough memory to handle jpeg2000 box\n"
}

predicate func_8(Variable vbox_1807, Variable vl_current_data_size_1811, ExprStmt target_8) {
		target_8.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vl_current_data_size_1811
		and target_8.getExpr().(AssignExpr).getRValue().(SubExpr).getLeftOperand().(ValueFieldAccess).getTarget().getName()="length"
		and target_8.getExpr().(AssignExpr).getRValue().(SubExpr).getLeftOperand().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vbox_1807
}

predicate func_9(Variable vl_current_data_size_1811, RelationalOperation target_9) {
		 (target_9 instanceof GTExpr or target_9 instanceof LTExpr)
		and target_9.getGreaterOperand().(VariableAccess).getTarget()=vl_current_data_size_1811
}

predicate func_10(Variable vl_current_data_1812, ExprStmt target_10) {
		target_10.getExpr().(FunctionCall).getTarget().hasName("free")
		and target_10.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vl_current_data_1812
}

from Function func, Parameter vstream_1803, Parameter vp_manager_1804, Variable vbox_1807, Variable vl_current_data_size_1811, Variable vl_current_data_1812, ExprStmt target_2, EqualityOperation target_3, FunctionCall target_4, ExprStmt target_5, ExprStmt target_6, ExprStmt target_7, ExprStmt target_8, RelationalOperation target_9, ExprStmt target_10
where
not func_0(vstream_1803, vp_manager_1804, vbox_1807, vl_current_data_size_1811, target_3, target_4, target_5, target_6, target_7, target_8, target_9)
and not func_1(vl_current_data_1812, target_10, target_2, func)
and func_2(vl_current_data_1812, func, target_2)
and func_3(target_3)
and func_4(vstream_1803, vp_manager_1804, vbox_1807, target_4)
and func_5(vstream_1803, vp_manager_1804, vl_current_data_size_1811, vl_current_data_1812, target_5)
and func_6(vp_manager_1804, vbox_1807, target_6)
and func_7(vp_manager_1804, target_7)
and func_8(vbox_1807, vl_current_data_size_1811, target_8)
and func_9(vl_current_data_size_1811, target_9)
and func_10(vl_current_data_1812, target_10)
and vstream_1803.getType().hasName("opj_stream_private_t *")
and vp_manager_1804.getType().hasName("opj_event_mgr_t *")
and vbox_1807.getType().hasName("opj_jp2_box_t")
and vl_current_data_size_1811.getType().hasName("OPJ_UINT32")
and vl_current_data_1812.getType().hasName("OPJ_BYTE *")
and vstream_1803.getParentScope+() = func
and vp_manager_1804.getParentScope+() = func
and vbox_1807.getParentScope+() = func
and vl_current_data_size_1811.getParentScope+() = func
and vl_current_data_1812.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
