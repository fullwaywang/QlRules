/**
 * @name freerdp-c367f65d42e0d2e1ca248998175180aa9c2eacd0-rdp_recv_tpkt_pdu
 * @id cpp/freerdp/c367f65d42e0d2e1ca248998175180aa9c2eacd0/rdp-recv-tpkt-pdu
 * @description freerdp-c367f65d42e0d2e1ca248998175180aa9c2eacd0-libfreerdp/core/rdp.c-rdp_recv_tpkt_pdu CVE-2020-11049
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vpduLength_1268, VariableAccess target_0) {
		target_0.getTarget()=vpduLength_1268
}

predicate func_1(Parameter vs_1263, Variable vpduLength_1268, VariableAccess target_1) {
		target_1.getTarget()=vpduLength_1268
		and target_1.getParent().(FunctionCall).getParent().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("Stream_SafeSeek")
		and target_1.getParent().(FunctionCall).getParent().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs_1263
}

predicate func_2(Parameter vs_1263, FunctionCall target_2) {
		target_2.getTarget().hasName("Stream_GetPosition")
		and not target_2.getTarget().hasName("Stream_GetRemainingLength")
		and target_2.getArgument(0).(VariableAccess).getTarget()=vs_1263
}

predicate func_3(Variable vpduLength_1268, Variable vheaderdiff_1322, BlockStmt target_57, VariableAccess target_3) {
		target_3.getTarget()=vpduLength_1268
		and target_3.getParent().(LTExpr).getGreaterOperand().(VariableAccess).getTarget()=vheaderdiff_1322
		and target_3.getParent().(LTExpr).getParent().(IfStmt).getThen()=target_57
}

predicate func_4(Variable vpduLength_1268, VariableAccess target_4) {
		target_4.getTarget()=vpduLength_1268
		and target_4.getParent().(FunctionCall).getParent().(ExprStmt).getExpr() instanceof FunctionCall
}

predicate func_6(Parameter vs_1263) {
	exists(FunctionCall target_6 |
		target_6.getTarget().hasName("Stream_StaticInit")
		and target_6.getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getType().hasName("wStream")
		and target_6.getArgument(1).(FunctionCall).getTarget().hasName("Stream_Pointer")
		and target_6.getArgument(1).(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs_1263
		and target_6.getArgument(2).(VariableAccess).getType().hasName("UINT16"))
}

predicate func_7(Parameter vrdp_1263, Parameter vs_1263) {
	exists(AddressOfExpr target_7 |
		target_7.getOperand().(VariableAccess).getType().hasName("wStream")
		and target_7.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("rdp_recv_data_pdu")
		and target_7.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vrdp_1263
		and target_7.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vs_1263)
}

predicate func_8(Parameter vrdp_1263, Parameter vs_1263) {
	exists(AddressOfExpr target_8 |
		target_8.getOperand().(VariableAccess).getType().hasName("wStream")
		and target_8.getParent().(FunctionCall).getParent().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("rdp_recv_deactivate_all")
		and target_8.getParent().(FunctionCall).getParent().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vrdp_1263
		and target_8.getParent().(FunctionCall).getParent().(NotExpr).getOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vs_1263)
}

predicate func_9(Parameter vrdp_1263, Parameter vs_1263) {
	exists(AddressOfExpr target_9 |
		target_9.getOperand().(VariableAccess).getType().hasName("wStream")
		and target_9.getParent().(FunctionCall).getParent().(ReturnStmt).getExpr().(FunctionCall).getTarget().hasName("rdp_recv_enhanced_security_redirection_packet")
		and target_9.getParent().(FunctionCall).getParent().(ReturnStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vrdp_1263
		and target_9.getParent().(FunctionCall).getParent().(ReturnStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vs_1263)
}

predicate func_10(Parameter vs_1263, Variable vpduLength_1268) {
	exists(AddressOfExpr target_10 |
		target_10.getOperand().(VariableAccess).getType().hasName("wStream")
		and target_10.getParent().(FunctionCall).getParent().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("Stream_SafeSeek")
		and target_10.getParent().(FunctionCall).getParent().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs_1263
		and target_10.getParent().(FunctionCall).getParent().(NotExpr).getOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vpduLength_1268)
}

predicate func_11(Function func) {
	exists(AddressOfExpr target_11 |
		target_11.getOperand().(VariableAccess).getType().hasName("wStream")
		and target_11.getParent().(FunctionCall).getParent().(AssignExpr).getRValue() instanceof FunctionCall
		and target_11.getEnclosingFunction() = func)
}

predicate func_12(Variable vdiff_1322, BlockStmt target_60, ExprStmt target_52, ExprStmt target_61) {
	exists(RelationalOperation target_12 |
		 (target_12 instanceof GTExpr or target_12 instanceof LTExpr)
		and target_12.getGreaterOperand().(VariableAccess).getTarget()=vdiff_1322
		and target_12.getLesserOperand().(Literal).getValue()="0"
		and target_12.getParent().(IfStmt).getThen()=target_60
		and target_52.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_12.getGreaterOperand().(VariableAccess).getLocation())
		and target_12.getGreaterOperand().(VariableAccess).getLocation().isBefore(target_61.getExpr().(FunctionCall).getArgument(8).(VariableAccess).getLocation()))
}

predicate func_14(Variable v_log_cached_ptr_1334, IfStmt target_14) {
		target_14.getCondition().(NotExpr).getOperand().(VariableAccess).getTarget()=v_log_cached_ptr_1334
		and target_14.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=v_log_cached_ptr_1334
		and target_14.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("WLog_Get")
		and target_14.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(StringLiteral).getValue()="com.freerdp.core.rdp"
}

predicate func_15(Variable v_log_cached_ptr_1334, FunctionCall target_15) {
		target_15.getTarget().hasName("WLog_IsLevelActive")
		and target_15.getArgument(0).(VariableAccess).getTarget()=v_log_cached_ptr_1334
		and target_15.getArgument(1).(Literal).getValue()="4"
}

predicate func_16(RelationalOperation target_42, Function func, ReturnStmt target_16) {
		target_16.getExpr().(UnaryMinusExpr).getValue()="-1"
		and target_16.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_42
		and target_16.getEnclosingFunction() = func
}

predicate func_17(Function func, SwitchCase target_17) {
		target_17.getExpr().(Literal).getValue()="7"
		and target_17.getEnclosingFunction() = func
}

predicate func_18(Variable vrc_1265, VariableAccess target_62, IfStmt target_18) {
		target_18.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vrc_1265
		and target_18.getCondition().(RelationalOperation).getGreaterOperand().(Literal).getValue()="0"
		and target_18.getThen().(ReturnStmt).getExpr().(VariableAccess).getTarget()=vrc_1265
		and target_18.getParent().(BlockStmt).getParent().(SwitchStmt).getExpr()=target_62
}

predicate func_19(Function func, SwitchCase target_19) {
		target_19.getExpr().(Literal).getValue()="6"
		and target_19.getEnclosingFunction() = func
}

predicate func_20(Function func, SwitchCase target_20) {
		target_20.getExpr().(Literal).getValue()="10"
		and target_20.getEnclosingFunction() = func
}

predicate func_21(Function func, SwitchCase target_21) {
		target_21.getExpr().(Literal).getValue()="66"
		and target_21.getEnclosingFunction() = func
}

predicate func_22(Function func, SwitchCase target_22) {
		target_22.getExpr().(Literal).getValue()="67"
		and target_22.getEnclosingFunction() = func
}

predicate func_23(Function func, SwitchCase target_23) {
		target_23.getExpr().(Literal).getValue()="65"
		and target_23.getEnclosingFunction() = func
}

predicate func_25(Parameter vs_1263, VariableAccess target_25) {
		target_25.getTarget()=vs_1263
		and target_25.getParent().(FunctionCall).getParent().(AssignExpr).getRValue() instanceof FunctionCall
}

predicate func_26(Parameter vs_1263, Variable vpduType_1267, Variable vpduLength_1268, VariableAccess target_26) {
		target_26.getTarget()=vs_1263
		and target_26.getParent().(FunctionCall).getParent().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("rdp_read_share_control_header")
		and target_26.getParent().(FunctionCall).getParent().(NotExpr).getOperand().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vpduLength_1268
		and target_26.getParent().(FunctionCall).getParent().(NotExpr).getOperand().(FunctionCall).getArgument(2).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vpduType_1267
}

predicate func_27(VariableAccess target_62, Function func, BreakStmt target_27) {
		target_27.toString() = "break;"
		and target_27.getParent().(BlockStmt).getParent().(SwitchStmt).getExpr()=target_62
		and target_27.getEnclosingFunction() = func
}

predicate func_28(VariableAccess target_62, Function func, BreakStmt target_28) {
		target_28.toString() = "break;"
		and target_28.getParent().(BlockStmt).getParent().(SwitchStmt).getExpr()=target_62
		and target_28.getEnclosingFunction() = func
}

predicate func_29(VariableAccess target_62, Function func, BreakStmt target_29) {
		target_29.toString() = "break;"
		and target_29.getParent().(BlockStmt).getParent().(SwitchStmt).getExpr()=target_62
		and target_29.getEnclosingFunction() = func
}

predicate func_30(Function func, SwitchCase target_30) {
		target_30.toString() = "default: "
		and target_30.getEnclosingFunction() = func
}

predicate func_31(VariableAccess target_62, Function func, BreakStmt target_31) {
		target_31.toString() = "break;"
		and target_31.getParent().(BlockStmt).getParent().(SwitchStmt).getExpr()=target_62
		and target_31.getEnclosingFunction() = func
}

predicate func_32(Variable vdiff_1322, VariableAccess target_32) {
		target_32.getTarget()=vdiff_1322
		and target_32.getParent().(AssignExpr).getLValue() = target_32
		and target_32.getParent().(AssignExpr).getRValue() instanceof SubExpr
}

predicate func_33(Variable vpduLength_1268, Variable vdiff_1322, BlockStmt target_63, VariableAccess target_33) {
		target_33.getTarget()=vdiff_1322
		and target_33.getParent().(NEExpr).getAnOperand().(VariableAccess).getTarget()=vpduLength_1268
		and target_33.getParent().(NEExpr).getParent().(IfStmt).getThen()=target_63
}

predicate func_39(Variable vstartheader_1322, VariableAccess target_39) {
		target_39.getTarget()=vstartheader_1322
		and target_39.getParent().(AssignExpr).getLValue() = target_39
		and target_39.getParent().(AssignExpr).getRValue() instanceof FunctionCall
}

predicate func_40(Parameter vs_1263, Variable vendheader_1322, Variable vstart_1322, AssignExpr target_40) {
		target_40.getLValue().(VariableAccess).getTarget()=vstart_1322
		and target_40.getRValue().(AssignExpr).getLValue().(VariableAccess).getTarget()=vendheader_1322
		and target_40.getRValue().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("Stream_GetPosition")
		and target_40.getRValue().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs_1263
}

predicate func_41(Variable vstartheader_1322, Variable vendheader_1322, Variable vheaderdiff_1322, AssignExpr target_41) {
		target_41.getLValue().(VariableAccess).getTarget()=vheaderdiff_1322
		and target_41.getRValue().(SubExpr).getLeftOperand().(VariableAccess).getTarget()=vendheader_1322
		and target_41.getRValue().(SubExpr).getRightOperand().(VariableAccess).getTarget()=vstartheader_1322
}

predicate func_42(Variable vpduLength_1268, Variable vheaderdiff_1322, BlockStmt target_57, RelationalOperation target_42) {
		 (target_42 instanceof GTExpr or target_42 instanceof LTExpr)
		and target_42.getLesserOperand().(VariableAccess).getTarget()=vpduLength_1268
		and target_42.getGreaterOperand().(VariableAccess).getTarget()=vheaderdiff_1322
		and target_42.getParent().(IfStmt).getThen()=target_57
}

predicate func_43(RelationalOperation target_42, Function func, DoStmt target_43) {
		target_43.getCondition() instanceof Literal
		and target_43.getStmt().(BlockStmt).getStmt(1) instanceof IfStmt
		and target_43.getStmt().(BlockStmt).getStmt(2).(DoStmt).getCondition() instanceof Literal
		and target_43.getStmt().(BlockStmt).getStmt(2).(DoStmt).getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition() instanceof FunctionCall
		and target_43.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_42
		and target_43.getEnclosingFunction() = func
}

/*predicate func_44(Variable v_log_cached_ptr_1334, Variable vpduLength_1268, Variable v__FUNCTION__, DoStmt target_44) {
		target_44.getCondition() instanceof Literal
		and target_44.getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition() instanceof FunctionCall
		and target_44.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("WLog_PrintMessage")
		and target_44.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=v_log_cached_ptr_1334
		and target_44.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1) instanceof Literal
		and target_44.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(Literal).getValue()="4"
		and target_44.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3) instanceof Literal
		and target_44.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(4) instanceof StringLiteral
		and target_44.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(5).(VariableAccess).getTarget()=v__FUNCTION__
		and target_44.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(6).(StringLiteral).getValue()="rdp_recv_tpkt_pdu: rdp_read_share_control_header() invalid pduLength %u"
		and target_44.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(7).(VariableAccess).getTarget()=vpduLength_1268
}

*/
/*predicate func_45(Variable v_log_cached_ptr_1334, Variable vpduLength_1268, Variable v__FUNCTION__, FunctionCall target_15, ExprStmt target_45) {
		target_45.getExpr().(FunctionCall).getTarget().hasName("WLog_PrintMessage")
		and target_45.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=v_log_cached_ptr_1334
		and target_45.getExpr().(FunctionCall).getArgument(1) instanceof Literal
		and target_45.getExpr().(FunctionCall).getArgument(2).(Literal).getValue()="4"
		and target_45.getExpr().(FunctionCall).getArgument(3) instanceof Literal
		and target_45.getExpr().(FunctionCall).getArgument(4) instanceof StringLiteral
		and target_45.getExpr().(FunctionCall).getArgument(5).(VariableAccess).getTarget()=v__FUNCTION__
		and target_45.getExpr().(FunctionCall).getArgument(6).(StringLiteral).getValue()="rdp_recv_tpkt_pdu: rdp_read_share_control_header() invalid pduLength %u"
		and target_45.getExpr().(FunctionCall).getArgument(7).(VariableAccess).getTarget()=vpduLength_1268
		and target_45.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_15
}

*/
predicate func_46(Variable vpduLength_1268, Variable vheaderdiff_1322, ExprStmt target_46) {
		target_46.getExpr().(AssignSubExpr).getLValue().(VariableAccess).getTarget()=vpduLength_1268
		and target_46.getExpr().(AssignSubExpr).getRValue().(VariableAccess).getTarget()=vheaderdiff_1322
}

predicate func_47(Parameter vrdp_1263, Parameter vs_1263, Variable vrc_1265, VariableAccess target_62, ExprStmt target_47) {
		target_47.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vrc_1265
		and target_47.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("rdp_recv_data_pdu")
		and target_47.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vrdp_1263
		and target_47.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vs_1263
		and target_47.getParent().(BlockStmt).getParent().(SwitchStmt).getExpr()=target_62
}

/*predicate func_48(Parameter vrdp_1263, Parameter vs_1263, ExprStmt target_64, NotExpr target_65, VariableAccess target_48) {
		target_48.getTarget()=vs_1263
		and target_48.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("rdp_recv_data_pdu")
		and target_48.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vrdp_1263
		and target_64.getExpr().(PostfixIncrExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_48.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_48.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_65.getOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
}

*/
predicate func_49(Parameter vrdp_1263, Parameter vs_1263, ExprStmt target_47, FunctionCall target_67, VariableAccess target_49) {
		target_49.getTarget()=vs_1263
		and target_49.getParent().(FunctionCall).getParent().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("rdp_recv_deactivate_all")
		and target_49.getParent().(FunctionCall).getParent().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vrdp_1263
		and target_47.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_49.getParent().(FunctionCall).getParent().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_49.getParent().(FunctionCall).getParent().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_67.getArgument(0).(VariableAccess).getLocation())
}

predicate func_50(Parameter vrdp_1263, Parameter vs_1263, NotExpr target_65, LogicalAndExpr target_68, NotExpr target_69, VariableAccess target_50) {
		target_50.getTarget()=vs_1263
		and target_50.getParent().(FunctionCall).getParent().(ReturnStmt).getExpr().(FunctionCall).getTarget().hasName("rdp_recv_enhanced_security_redirection_packet")
		and target_50.getParent().(FunctionCall).getParent().(ReturnStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vrdp_1263
		and target_65.getOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_50.getParent().(FunctionCall).getParent().(ReturnStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_50.getParent().(FunctionCall).getParent().(ReturnStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_68.getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_50.getLocation().isBefore(target_69.getOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
}

predicate func_51(Parameter vs_1263, Variable vend_1322, ExprStmt target_51) {
		target_51.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vend_1322
		and target_51.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("Stream_GetPosition")
		and target_51.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs_1263
}

predicate func_52(Variable vstart_1322, Variable vend_1322, Variable vdiff_1322, ExprStmt target_52) {
		target_52.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vdiff_1322
		and target_52.getExpr().(AssignExpr).getRValue().(SubExpr).getLeftOperand().(VariableAccess).getTarget()=vend_1322
		and target_52.getExpr().(AssignExpr).getRValue().(SubExpr).getRightOperand().(VariableAccess).getTarget()=vstart_1322
}

predicate func_53(Variable v_log_cached_ptr_1383, Parameter vs_1263, Variable vpduLength_1268, Variable vdiff_1322, IfStmt target_53) {
		target_53.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vdiff_1322
		and target_53.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vpduLength_1268
		and target_53.getThen().(BlockStmt).getStmt(0).(DoStmt).getCondition() instanceof Literal
		and target_53.getThen().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(NotExpr).getOperand().(VariableAccess).getTarget()=v_log_cached_ptr_1383
		and target_53.getThen().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(2).(DoStmt).getCondition() instanceof Literal
		and target_53.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("Stream_SafeSeek")
		and target_53.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs_1263
		and target_53.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vpduLength_1268
		and target_53.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-1"
}

/*predicate func_54(Parameter vs_1263, Variable vpduLength_1268, EqualityOperation target_70, IfStmt target_54) {
		target_54.getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("Stream_SafeSeek")
		and target_54.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs_1263
		and target_54.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vpduLength_1268
		and target_54.getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-1"
		and target_54.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_70
}

*/
/*predicate func_55(Parameter vs_1263, Variable vpduLength_1268, ExprStmt target_51, NotExpr target_71, EqualityOperation target_70, VariableAccess target_55) {
		target_55.getTarget()=vs_1263
		and target_55.getParent().(FunctionCall).getParent().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("Stream_SafeSeek")
		and target_55.getParent().(FunctionCall).getParent().(NotExpr).getOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vpduLength_1268
		and target_51.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_55.getLocation())
		and target_55.getLocation().isBefore(target_71.getOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_70.getAnOperand().(VariableAccess).getLocation().isBefore(target_55.getParent().(FunctionCall).getParent().(NotExpr).getOperand().(FunctionCall).getArgument(1).(VariableAccess).getLocation())
}

*/
/*predicate func_56(Parameter vs_1263, Variable vpduLength_1268, ExprStmt target_51, NotExpr target_71, EqualityOperation target_70, VariableAccess target_56) {
		target_56.getTarget()=vpduLength_1268
		and target_56.getParent().(FunctionCall).getParent().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("Stream_SafeSeek")
		and target_56.getParent().(FunctionCall).getParent().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs_1263
		and target_51.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_56.getParent().(FunctionCall).getParent().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_56.getParent().(FunctionCall).getParent().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_71.getOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_70.getAnOperand().(VariableAccess).getLocation().isBefore(target_56.getLocation())
}

*/
predicate func_57(BlockStmt target_57) {
		target_57.getStmt(0) instanceof DoStmt
		and target_57.getStmt(1) instanceof ReturnStmt
}

predicate func_60(BlockStmt target_60) {
		target_60.getStmt(0).(DoStmt).getCondition() instanceof Literal
		and target_60.getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("WLog_Get")
		and target_60.getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(2).(DoStmt).getCondition() instanceof Literal
		and target_60.getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(2).(DoStmt).getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(FunctionCall).getTarget().hasName("WLog_IsLevelActive")
		and target_60.getStmt(1).(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-1"
}

predicate func_61(Variable v_log_cached_ptr_1383, Variable v__FUNCTION__, Variable vdiff_1322, ExprStmt target_61) {
		target_61.getExpr().(FunctionCall).getTarget().hasName("WLog_PrintMessage")
		and target_61.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=v_log_cached_ptr_1383
		and target_61.getExpr().(FunctionCall).getArgument(1) instanceof Literal
		and target_61.getExpr().(FunctionCall).getArgument(2).(Literal).getValue()="3"
		and target_61.getExpr().(FunctionCall).getArgument(3) instanceof Literal
		and target_61.getExpr().(FunctionCall).getArgument(4) instanceof StringLiteral
		and target_61.getExpr().(FunctionCall).getArgument(5).(VariableAccess).getTarget()=v__FUNCTION__
		and target_61.getExpr().(FunctionCall).getArgument(6).(StringLiteral).getValue()="pduType %s not properly parsed, %zd bytes remaining unhandled. Skipping."
		and target_61.getExpr().(FunctionCall).getArgument(7).(FunctionCall).getTarget().hasName("pdu_type_to_str")
		and target_61.getExpr().(FunctionCall).getArgument(8).(VariableAccess).getTarget()=vdiff_1322
}

predicate func_62(Variable vpduType_1267, VariableAccess target_62) {
		target_62.getTarget()=vpduType_1267
}

predicate func_63(Variable v_log_cached_ptr_1383, BlockStmt target_63) {
		target_63.getStmt(0).(DoStmt).getCondition() instanceof Literal
		and target_63.getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(NotExpr).getOperand().(VariableAccess).getTarget()=v_log_cached_ptr_1383
		and target_63.getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=v_log_cached_ptr_1383
		and target_63.getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("WLog_Get")
		and target_63.getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(2).(DoStmt).getCondition() instanceof Literal
		and target_63.getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(2).(DoStmt).getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(FunctionCall).getTarget().hasName("WLog_IsLevelActive")
}

predicate func_64(Parameter vrdp_1263, ExprStmt target_64) {
		target_64.getExpr().(PostfixIncrExpr).getOperand().(PointerFieldAccess).getTarget().getName()="inPackets"
		and target_64.getExpr().(PostfixIncrExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vrdp_1263
}

predicate func_65(Parameter vrdp_1263, Parameter vs_1263, NotExpr target_65) {
		target_65.getOperand().(FunctionCall).getTarget().hasName("rdp_recv_deactivate_all")
		and target_65.getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vrdp_1263
		and target_65.getOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vs_1263
}

predicate func_67(Parameter vrdp_1263, Parameter vs_1263, FunctionCall target_67) {
		target_67.getTarget().hasName("rdp_recv_enhanced_security_redirection_packet")
		and target_67.getArgument(0).(VariableAccess).getTarget()=vrdp_1263
		and target_67.getArgument(1).(VariableAccess).getTarget()=vs_1263
}

predicate func_68(Parameter vrdp_1263, LogicalAndExpr target_68) {
		target_68.getAnOperand().(PointerFieldAccess).getTarget().getName()="messageChannelId"
		and target_68.getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="mcs"
		and target_68.getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vrdp_1263
		and target_68.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="messageChannelId"
		and target_68.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="mcs"
		and target_68.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vrdp_1263
}

predicate func_69(Parameter vs_1263, Variable vpduLength_1268, NotExpr target_69) {
		target_69.getOperand().(FunctionCall).getTarget().hasName("Stream_SafeSeek")
		and target_69.getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs_1263
		and target_69.getOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vpduLength_1268
}

predicate func_70(Variable vpduLength_1268, Variable vdiff_1322, EqualityOperation target_70) {
		target_70.getAnOperand().(VariableAccess).getTarget()=vdiff_1322
		and target_70.getAnOperand().(VariableAccess).getTarget()=vpduLength_1268
}

predicate func_71(Parameter vs_1263, NotExpr target_71) {
		target_71.getOperand().(FunctionCall).getTarget().hasName("rdp_read_security_header")
		and target_71.getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs_1263
		and target_71.getOperand().(FunctionCall).getArgument(2).(Literal).getValue()="0"
}

from Function func, Variable v_log_cached_ptr_1334, Variable v_log_cached_ptr_1383, Parameter vrdp_1263, Parameter vs_1263, Variable vrc_1265, Variable vpduType_1267, Variable vpduLength_1268, Variable v__FUNCTION__, Variable vstartheader_1322, Variable vendheader_1322, Variable vstart_1322, Variable vend_1322, Variable vdiff_1322, Variable vheaderdiff_1322, VariableAccess target_0, VariableAccess target_1, FunctionCall target_2, VariableAccess target_3, VariableAccess target_4, IfStmt target_14, FunctionCall target_15, ReturnStmt target_16, SwitchCase target_17, IfStmt target_18, SwitchCase target_19, SwitchCase target_20, SwitchCase target_21, SwitchCase target_22, SwitchCase target_23, VariableAccess target_25, VariableAccess target_26, BreakStmt target_27, BreakStmt target_28, BreakStmt target_29, SwitchCase target_30, BreakStmt target_31, VariableAccess target_32, VariableAccess target_33, VariableAccess target_39, AssignExpr target_40, AssignExpr target_41, RelationalOperation target_42, DoStmt target_43, ExprStmt target_46, ExprStmt target_47, VariableAccess target_49, VariableAccess target_50, ExprStmt target_51, ExprStmt target_52, IfStmt target_53, BlockStmt target_57, BlockStmt target_60, ExprStmt target_61, VariableAccess target_62, BlockStmt target_63, ExprStmt target_64, NotExpr target_65, FunctionCall target_67, LogicalAndExpr target_68, NotExpr target_69, EqualityOperation target_70, NotExpr target_71
where
func_0(vpduLength_1268, target_0)
and func_1(vs_1263, vpduLength_1268, target_1)
and func_2(vs_1263, target_2)
and func_3(vpduLength_1268, vheaderdiff_1322, target_57, target_3)
and func_4(vpduLength_1268, target_4)
and not func_6(vs_1263)
and not func_7(vrdp_1263, vs_1263)
and not func_8(vrdp_1263, vs_1263)
and not func_9(vrdp_1263, vs_1263)
and not func_10(vs_1263, vpduLength_1268)
and not func_11(func)
and not func_12(vdiff_1322, target_60, target_52, target_61)
and func_14(v_log_cached_ptr_1334, target_14)
and func_15(v_log_cached_ptr_1334, target_15)
and func_16(target_42, func, target_16)
and func_17(func, target_17)
and func_18(vrc_1265, target_62, target_18)
and func_19(func, target_19)
and func_20(func, target_20)
and func_21(func, target_21)
and func_22(func, target_22)
and func_23(func, target_23)
and func_25(vs_1263, target_25)
and func_26(vs_1263, vpduType_1267, vpduLength_1268, target_26)
and func_27(target_62, func, target_27)
and func_28(target_62, func, target_28)
and func_29(target_62, func, target_29)
and func_30(func, target_30)
and func_31(target_62, func, target_31)
and func_32(vdiff_1322, target_32)
and func_33(vpduLength_1268, vdiff_1322, target_63, target_33)
and func_39(vstartheader_1322, target_39)
and func_40(vs_1263, vendheader_1322, vstart_1322, target_40)
and func_41(vstartheader_1322, vendheader_1322, vheaderdiff_1322, target_41)
and func_42(vpduLength_1268, vheaderdiff_1322, target_57, target_42)
and func_43(target_42, func, target_43)
and func_46(vpduLength_1268, vheaderdiff_1322, target_46)
and func_47(vrdp_1263, vs_1263, vrc_1265, target_62, target_47)
and func_49(vrdp_1263, vs_1263, target_47, target_67, target_49)
and func_50(vrdp_1263, vs_1263, target_65, target_68, target_69, target_50)
and func_51(vs_1263, vend_1322, target_51)
and func_52(vstart_1322, vend_1322, vdiff_1322, target_52)
and func_53(v_log_cached_ptr_1383, vs_1263, vpduLength_1268, vdiff_1322, target_53)
and func_57(target_57)
and func_60(target_60)
and func_61(v_log_cached_ptr_1383, v__FUNCTION__, vdiff_1322, target_61)
and func_62(vpduType_1267, target_62)
and func_63(v_log_cached_ptr_1383, target_63)
and func_64(vrdp_1263, target_64)
and func_65(vrdp_1263, vs_1263, target_65)
and func_67(vrdp_1263, vs_1263, target_67)
and func_68(vrdp_1263, target_68)
and func_69(vs_1263, vpduLength_1268, target_69)
and func_70(vpduLength_1268, vdiff_1322, target_70)
and func_71(vs_1263, target_71)
and v_log_cached_ptr_1334.getType().hasName("wLog *")
and v_log_cached_ptr_1383.getType().hasName("wLog *")
and vrdp_1263.getType().hasName("rdpRdp *")
and vs_1263.getType().hasName("wStream *")
and vrc_1265.getType().hasName("int")
and vpduType_1267.getType().hasName("UINT16")
and vpduLength_1268.getType().hasName("UINT16")
and v__FUNCTION__.getType() instanceof ArrayType
and vstartheader_1322.getType().hasName("size_t")
and vendheader_1322.getType().hasName("size_t")
and vstart_1322.getType().hasName("size_t")
and vend_1322.getType().hasName("size_t")
and vdiff_1322.getType().hasName("size_t")
and vheaderdiff_1322.getType().hasName("size_t")
and v_log_cached_ptr_1334.getParentScope+() = func
and v_log_cached_ptr_1383.getParentScope+() = func
and vrdp_1263.getParentScope+() = func
and vs_1263.getParentScope+() = func
and vrc_1265.getParentScope+() = func
and vpduType_1267.getParentScope+() = func
and vpduLength_1268.getParentScope+() = func
and not v__FUNCTION__.getParentScope+() = func
and vstartheader_1322.getParentScope+() = func
and vendheader_1322.getParentScope+() = func
and vstart_1322.getParentScope+() = func
and vend_1322.getParentScope+() = func
and vdiff_1322.getParentScope+() = func
and vheaderdiff_1322.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
