/**
 * @name openjpeg-3df347eded5e0b690b1de72c48136ebbcfeef527-opj_j2k_read_tile_header
 * @id cpp/openjpeg/3df347eded5e0b690b1de72c48136ebbcfeef527/opj-j2k-read-tile-header
 * @description openjpeg-3df347eded5e0b690b1de72c48136ebbcfeef527-src/lib/openjp2/j2k.c-opj_j2k_read_tile_header CVE-2014-7945
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vl_marker_size_7562, BlockStmt target_10, ExprStmt target_11, RelationalOperation target_5) {
	exists(RelationalOperation target_0 |
		 (target_0 instanceof GTExpr or target_0 instanceof LTExpr)
		and target_0.getLesserOperand().(VariableAccess).getTarget()=vl_marker_size_7562
		and target_0.getGreaterOperand().(Literal).getValue()="2"
		and target_0.getParent().(IfStmt).getThen()=target_10
		and target_11.getExpr().(AssignSubExpr).getLValue().(VariableAccess).getLocation().isBefore(target_0.getLesserOperand().(VariableAccess).getLocation())
		and target_0.getLesserOperand().(VariableAccess).getLocation().isBefore(target_5.getGreaterOperand().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vp_manager_7559, RelationalOperation target_5, ExprStmt target_12, ExprStmt target_13) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(FunctionCall).getTarget().hasName("opj_event_msg")
		and target_1.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vp_manager_7559
		and target_1.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="1"
		and target_1.getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="Inconsistent marker size\n"
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0)=target_1
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_5
		and target_12.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_1.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_1.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_13.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

predicate func_2(RelationalOperation target_5, Function func) {
	exists(ReturnStmt target_2 |
		target_2.getExpr().(Literal).getValue()="0"
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1)=target_2
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_5
		and target_2.getEnclosingFunction() = func)
}

predicate func_3(Parameter vp_stream_7558, Parameter vp_manager_7559, Variable vl_marker_size_7562, LogicalAndExpr target_14, EqualityOperation target_15, ExprStmt target_13, ExprStmt target_8) {
	exists(IfStmt target_3 |
		target_3.getCondition() instanceof RelationalOperation
		and target_3.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vl_marker_size_7562
		and target_3.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(FunctionCall).getTarget().hasName("opj_stream_get_number_byte_left")
		and target_3.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vp_stream_7558
		and target_3.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("opj_event_msg")
		and target_3.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vp_manager_7559
		and target_3.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="1"
		and target_3.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="Marker size inconsistent with stream length\n"
		and target_3.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(Literal).getValue()="0"
		and target_3.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getType().hasName("OPJ_BYTE *")
		and target_3.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue() instanceof FunctionCall
		and target_3.getThen().(BlockStmt).getStmt(3) instanceof IfStmt
		and target_3.getThen().(BlockStmt).getStmt(4) instanceof ExprStmt
		and target_3.getThen().(BlockStmt).getStmt(5) instanceof ExprStmt
		and target_14.getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_3.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_3.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_15.getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_13.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_3.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_8.getExpr().(AssignExpr).getRValue().(VariableAccess).getLocation().isBefore(target_3.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation()))
}

predicate func_5(Variable vl_marker_size_7562, Parameter vp_j2k_7551, BlockStmt target_10, RelationalOperation target_5) {
		 (target_5 instanceof GTExpr or target_5 instanceof LTExpr)
		and target_5.getGreaterOperand().(VariableAccess).getTarget()=vl_marker_size_7562
		and target_5.getLesserOperand().(ValueFieldAccess).getTarget().getName()="m_header_data_size"
		and target_5.getLesserOperand().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="m_decoder"
		and target_5.getLesserOperand().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="m_specific_param"
		and target_5.getLesserOperand().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vp_j2k_7551
		and target_5.getParent().(IfStmt).getThen()=target_10
}

predicate func_6(Parameter vp_manager_7559, Variable vnew_header_data_7626, RelationalOperation target_5, IfStmt target_6) {
		target_6.getCondition().(NotExpr).getOperand().(VariableAccess).getTarget()=vnew_header_data_7626
		and target_6.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("free")
		and target_6.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(ValueFieldAccess).getTarget().getName()="m_header_data"
		and target_6.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="m_decoder"
		and target_6.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="m_specific_param"
		and target_6.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="m_header_data"
		and target_6.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="m_decoder"
		and target_6.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="m_specific_param"
		and target_6.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_6.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="m_header_data_size"
		and target_6.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="m_decoder"
		and target_6.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="m_specific_param"
		and target_6.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_6.getThen().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("opj_event_msg")
		and target_6.getThen().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vp_manager_7559
		and target_6.getThen().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="1"
		and target_6.getThen().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="Not enough memory to read header\n"
		and target_6.getThen().(BlockStmt).getStmt(4).(ReturnStmt).getExpr().(Literal).getValue()="0"
		and target_6.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_5
}

predicate func_7(Variable vnew_header_data_7626, Parameter vp_j2k_7551, RelationalOperation target_5, ExprStmt target_7) {
		target_7.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="m_header_data"
		and target_7.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="m_decoder"
		and target_7.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="m_specific_param"
		and target_7.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vp_j2k_7551
		and target_7.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vnew_header_data_7626
		and target_7.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_5
}

predicate func_8(Variable vl_marker_size_7562, Parameter vp_j2k_7551, RelationalOperation target_5, ExprStmt target_8) {
		target_8.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="m_header_data_size"
		and target_8.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="m_decoder"
		and target_8.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="m_specific_param"
		and target_8.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vp_j2k_7551
		and target_8.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vl_marker_size_7562
		and target_8.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_5
}

predicate func_9(Variable vl_marker_size_7562, Parameter vp_j2k_7551, FunctionCall target_9) {
		target_9.getTarget().hasName("realloc")
		and target_9.getArgument(0).(ValueFieldAccess).getTarget().getName()="m_header_data"
		and target_9.getArgument(0).(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="m_decoder"
		and target_9.getArgument(0).(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="m_specific_param"
		and target_9.getArgument(0).(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vp_j2k_7551
		and target_9.getArgument(1).(VariableAccess).getTarget()=vl_marker_size_7562
}

predicate func_10(BlockStmt target_10) {
		target_10.getStmt(1) instanceof IfStmt
		and target_10.getStmt(2) instanceof ExprStmt
		and target_10.getStmt(3) instanceof ExprStmt
}

predicate func_11(Variable vl_marker_size_7562, ExprStmt target_11) {
		target_11.getExpr().(AssignSubExpr).getLValue().(VariableAccess).getTarget()=vl_marker_size_7562
		and target_11.getExpr().(AssignSubExpr).getRValue().(Literal).getValue()="2"
}

predicate func_12(Parameter vp_manager_7559, ExprStmt target_12) {
		target_12.getExpr().(FunctionCall).getTarget().hasName("opj_event_msg")
		and target_12.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vp_manager_7559
		and target_12.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="1"
		and target_12.getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="Marker is not compliant with its position\n"
}

predicate func_13(Parameter vp_manager_7559, ExprStmt target_13) {
		target_13.getExpr().(FunctionCall).getTarget().hasName("opj_event_msg")
		and target_13.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vp_manager_7559
		and target_13.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="1"
		and target_13.getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="Not enough memory to read header\n"
}

predicate func_14(Parameter vp_stream_7558, LogicalAndExpr target_14) {
		target_14.getAnOperand().(EqualityOperation).getAnOperand().(HexLiteral).getValue()="32896"
		and target_14.getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getTarget().hasName("opj_stream_get_number_byte_left")
		and target_14.getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vp_stream_7558
		and target_14.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
}

predicate func_15(Parameter vp_stream_7558, Parameter vp_manager_7559, Variable vl_marker_size_7562, Parameter vp_j2k_7551, EqualityOperation target_15) {
		target_15.getAnOperand().(FunctionCall).getTarget().hasName("opj_stream_read_data")
		and target_15.getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vp_stream_7558
		and target_15.getAnOperand().(FunctionCall).getArgument(1).(ValueFieldAccess).getTarget().getName()="m_header_data"
		and target_15.getAnOperand().(FunctionCall).getArgument(1).(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="m_decoder"
		and target_15.getAnOperand().(FunctionCall).getArgument(1).(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="m_specific_param"
		and target_15.getAnOperand().(FunctionCall).getArgument(1).(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vp_j2k_7551
		and target_15.getAnOperand().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vl_marker_size_7562
		and target_15.getAnOperand().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vp_manager_7559
		and target_15.getAnOperand().(VariableAccess).getTarget()=vl_marker_size_7562
}

from Function func, Parameter vp_stream_7558, Parameter vp_manager_7559, Variable vl_marker_size_7562, Variable vnew_header_data_7626, Parameter vp_j2k_7551, RelationalOperation target_5, IfStmt target_6, ExprStmt target_7, ExprStmt target_8, FunctionCall target_9, BlockStmt target_10, ExprStmt target_11, ExprStmt target_12, ExprStmt target_13, LogicalAndExpr target_14, EqualityOperation target_15
where
not func_0(vl_marker_size_7562, target_10, target_11, target_5)
and not func_1(vp_manager_7559, target_5, target_12, target_13)
and not func_2(target_5, func)
and not func_3(vp_stream_7558, vp_manager_7559, vl_marker_size_7562, target_14, target_15, target_13, target_8)
and func_5(vl_marker_size_7562, vp_j2k_7551, target_10, target_5)
and func_6(vp_manager_7559, vnew_header_data_7626, target_5, target_6)
and func_7(vnew_header_data_7626, vp_j2k_7551, target_5, target_7)
and func_8(vl_marker_size_7562, vp_j2k_7551, target_5, target_8)
and func_9(vl_marker_size_7562, vp_j2k_7551, target_9)
and func_10(target_10)
and func_11(vl_marker_size_7562, target_11)
and func_12(vp_manager_7559, target_12)
and func_13(vp_manager_7559, target_13)
and func_14(vp_stream_7558, target_14)
and func_15(vp_stream_7558, vp_manager_7559, vl_marker_size_7562, vp_j2k_7551, target_15)
and vp_stream_7558.getType().hasName("opj_stream_private_t *")
and vp_manager_7559.getType().hasName("opj_event_mgr_t *")
and vl_marker_size_7562.getType().hasName("OPJ_UINT32")
and vnew_header_data_7626.getType().hasName("OPJ_BYTE *")
and vp_j2k_7551.getType().hasName("opj_j2k_t *")
and vp_stream_7558.getParentScope+() = func
and vp_manager_7559.getParentScope+() = func
and vl_marker_size_7562.getParentScope+() = func
and vnew_header_data_7626.getParentScope+() = func
and vp_j2k_7551.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
