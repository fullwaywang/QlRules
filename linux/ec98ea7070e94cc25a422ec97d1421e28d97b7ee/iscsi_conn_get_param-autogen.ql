/**
 * @name linux-ec98ea7070e94cc25a422ec97d1421e28d97b7ee-iscsi_conn_get_param
 * @id cpp/linux/ec98ea7070e94cc25a422ec97d1421e28d97b7ee/iscsi_conn_get_param
 * @description linux-ec98ea7070e94cc25a422ec97d1421e28d97b7ee-iscsi_conn_get_param 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Parameter vbuf_3604, Variable vconn_3606) {
	exists(FunctionCall target_0 |
		target_0.getTarget().hasName("sprintf")
		and not target_0.getTarget().hasName("sysfs_emit")
		and target_0.getArgument(0).(VariableAccess).getTarget()=vbuf_3604
		and target_0.getArgument(1).(StringLiteral).getValue()="%u\n"
		and target_0.getArgument(2).(PointerFieldAccess).getTarget().getName()="ping_timeout"
		and target_0.getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn_3606)
}

predicate func_1(Parameter vbuf_3604, Variable vconn_3606) {
	exists(FunctionCall target_1 |
		target_1.getTarget().hasName("sprintf")
		and not target_1.getTarget().hasName("sysfs_emit")
		and target_1.getArgument(0).(VariableAccess).getTarget()=vbuf_3604
		and target_1.getArgument(1).(StringLiteral).getValue()="%u\n"
		and target_1.getArgument(2).(PointerFieldAccess).getTarget().getName()="recv_timeout"
		and target_1.getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn_3606)
}

predicate func_2(Parameter vbuf_3604, Variable vconn_3606) {
	exists(FunctionCall target_2 |
		target_2.getTarget().hasName("sprintf")
		and not target_2.getTarget().hasName("sysfs_emit")
		and target_2.getArgument(0).(VariableAccess).getTarget()=vbuf_3604
		and target_2.getArgument(1).(StringLiteral).getValue()="%u\n"
		and target_2.getArgument(2).(PointerFieldAccess).getTarget().getName()="max_recv_dlength"
		and target_2.getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn_3606)
}

predicate func_3(Parameter vbuf_3604, Variable vconn_3606) {
	exists(FunctionCall target_3 |
		target_3.getTarget().hasName("sprintf")
		and not target_3.getTarget().hasName("sysfs_emit")
		and target_3.getArgument(0).(VariableAccess).getTarget()=vbuf_3604
		and target_3.getArgument(1).(StringLiteral).getValue()="%u\n"
		and target_3.getArgument(2).(PointerFieldAccess).getTarget().getName()="max_xmit_dlength"
		and target_3.getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn_3606)
}

predicate func_4(Parameter vbuf_3604, Variable vconn_3606) {
	exists(FunctionCall target_4 |
		target_4.getTarget().hasName("sprintf")
		and not target_4.getTarget().hasName("sysfs_emit")
		and target_4.getArgument(0).(VariableAccess).getTarget()=vbuf_3604
		and target_4.getArgument(1).(StringLiteral).getValue()="%d\n"
		and target_4.getArgument(2).(PointerFieldAccess).getTarget().getName()="hdrdgst_en"
		and target_4.getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn_3606)
}

predicate func_5(Parameter vbuf_3604, Variable vconn_3606) {
	exists(FunctionCall target_5 |
		target_5.getTarget().hasName("sprintf")
		and not target_5.getTarget().hasName("sysfs_emit")
		and target_5.getArgument(0).(VariableAccess).getTarget()=vbuf_3604
		and target_5.getArgument(1).(StringLiteral).getValue()="%d\n"
		and target_5.getArgument(2).(PointerFieldAccess).getTarget().getName()="datadgst_en"
		and target_5.getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn_3606)
}

predicate func_6(Parameter vbuf_3604, Variable vconn_3606) {
	exists(FunctionCall target_6 |
		target_6.getTarget().hasName("sprintf")
		and not target_6.getTarget().hasName("sysfs_emit")
		and target_6.getArgument(0).(VariableAccess).getTarget()=vbuf_3604
		and target_6.getArgument(1).(StringLiteral).getValue()="%d\n"
		and target_6.getArgument(2).(PointerFieldAccess).getTarget().getName()="ifmarker_en"
		and target_6.getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn_3606)
}

predicate func_7(Parameter vbuf_3604, Variable vconn_3606) {
	exists(FunctionCall target_7 |
		target_7.getTarget().hasName("sprintf")
		and not target_7.getTarget().hasName("sysfs_emit")
		and target_7.getArgument(0).(VariableAccess).getTarget()=vbuf_3604
		and target_7.getArgument(1).(StringLiteral).getValue()="%d\n"
		and target_7.getArgument(2).(PointerFieldAccess).getTarget().getName()="ofmarker_en"
		and target_7.getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn_3606)
}

predicate func_8(Parameter vbuf_3604, Variable vconn_3606) {
	exists(FunctionCall target_8 |
		target_8.getTarget().hasName("sprintf")
		and not target_8.getTarget().hasName("sysfs_emit")
		and target_8.getArgument(0).(VariableAccess).getTarget()=vbuf_3604
		and target_8.getArgument(1).(StringLiteral).getValue()="%u\n"
		and target_8.getArgument(2).(PointerFieldAccess).getTarget().getName()="exp_statsn"
		and target_8.getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn_3606)
}

predicate func_9(Parameter vbuf_3604, Variable vconn_3606) {
	exists(FunctionCall target_9 |
		target_9.getTarget().hasName("sprintf")
		and not target_9.getTarget().hasName("sysfs_emit")
		and target_9.getArgument(0).(VariableAccess).getTarget()=vbuf_3604
		and target_9.getArgument(1).(StringLiteral).getValue()="%d\n"
		and target_9.getArgument(2).(PointerFieldAccess).getTarget().getName()="persistent_port"
		and target_9.getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn_3606)
}

predicate func_10(Parameter vbuf_3604, Variable vconn_3606) {
	exists(FunctionCall target_10 |
		target_10.getTarget().hasName("sprintf")
		and not target_10.getTarget().hasName("sysfs_emit")
		and target_10.getArgument(0).(VariableAccess).getTarget()=vbuf_3604
		and target_10.getArgument(1).(StringLiteral).getValue()="%s\n"
		and target_10.getArgument(2).(PointerFieldAccess).getTarget().getName()="persistent_address"
		and target_10.getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn_3606)
}

predicate func_11(Parameter vbuf_3604, Variable vconn_3606) {
	exists(FunctionCall target_11 |
		target_11.getTarget().hasName("sprintf")
		and not target_11.getTarget().hasName("sysfs_emit")
		and target_11.getArgument(0).(VariableAccess).getTarget()=vbuf_3604
		and target_11.getArgument(1).(StringLiteral).getValue()="%u\n"
		and target_11.getArgument(2).(PointerFieldAccess).getTarget().getName()="statsn"
		and target_11.getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn_3606)
}

predicate func_12(Parameter vbuf_3604, Variable vconn_3606) {
	exists(FunctionCall target_12 |
		target_12.getTarget().hasName("sprintf")
		and not target_12.getTarget().hasName("sysfs_emit")
		and target_12.getArgument(0).(VariableAccess).getTarget()=vbuf_3604
		and target_12.getArgument(1).(StringLiteral).getValue()="%u\n"
		and target_12.getArgument(2).(PointerFieldAccess).getTarget().getName()="max_segment_size"
		and target_12.getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn_3606)
}

predicate func_13(Parameter vbuf_3604, Variable vconn_3606) {
	exists(FunctionCall target_13 |
		target_13.getTarget().hasName("sprintf")
		and not target_13.getTarget().hasName("sysfs_emit")
		and target_13.getArgument(0).(VariableAccess).getTarget()=vbuf_3604
		and target_13.getArgument(1).(StringLiteral).getValue()="%u\n"
		and target_13.getArgument(2).(PointerFieldAccess).getTarget().getName()="keepalive_tmo"
		and target_13.getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn_3606)
}

predicate func_14(Parameter vbuf_3604, Variable vconn_3606) {
	exists(FunctionCall target_14 |
		target_14.getTarget().hasName("sprintf")
		and not target_14.getTarget().hasName("sysfs_emit")
		and target_14.getArgument(0).(VariableAccess).getTarget()=vbuf_3604
		and target_14.getArgument(1).(StringLiteral).getValue()="%u\n"
		and target_14.getArgument(2).(PointerFieldAccess).getTarget().getName()="local_port"
		and target_14.getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn_3606)
}

predicate func_15(Parameter vbuf_3604, Variable vconn_3606) {
	exists(FunctionCall target_15 |
		target_15.getTarget().hasName("sprintf")
		and not target_15.getTarget().hasName("sysfs_emit")
		and target_15.getArgument(0).(VariableAccess).getTarget()=vbuf_3604
		and target_15.getArgument(1).(StringLiteral).getValue()="%u\n"
		and target_15.getArgument(2).(PointerFieldAccess).getTarget().getName()="tcp_timestamp_stat"
		and target_15.getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn_3606)
}

predicate func_16(Parameter vbuf_3604, Variable vconn_3606) {
	exists(FunctionCall target_16 |
		target_16.getTarget().hasName("sprintf")
		and not target_16.getTarget().hasName("sysfs_emit")
		and target_16.getArgument(0).(VariableAccess).getTarget()=vbuf_3604
		and target_16.getArgument(1).(StringLiteral).getValue()="%u\n"
		and target_16.getArgument(2).(PointerFieldAccess).getTarget().getName()="tcp_nagle_disable"
		and target_16.getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn_3606)
}

predicate func_17(Parameter vbuf_3604, Variable vconn_3606) {
	exists(FunctionCall target_17 |
		target_17.getTarget().hasName("sprintf")
		and not target_17.getTarget().hasName("sysfs_emit")
		and target_17.getArgument(0).(VariableAccess).getTarget()=vbuf_3604
		and target_17.getArgument(1).(StringLiteral).getValue()="%u\n"
		and target_17.getArgument(2).(PointerFieldAccess).getTarget().getName()="tcp_wsf_disable"
		and target_17.getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn_3606)
}

predicate func_18(Parameter vbuf_3604, Variable vconn_3606) {
	exists(FunctionCall target_18 |
		target_18.getTarget().hasName("sprintf")
		and not target_18.getTarget().hasName("sysfs_emit")
		and target_18.getArgument(0).(VariableAccess).getTarget()=vbuf_3604
		and target_18.getArgument(1).(StringLiteral).getValue()="%u\n"
		and target_18.getArgument(2).(PointerFieldAccess).getTarget().getName()="tcp_timer_scale"
		and target_18.getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn_3606)
}

predicate func_19(Parameter vbuf_3604, Variable vconn_3606) {
	exists(FunctionCall target_19 |
		target_19.getTarget().hasName("sprintf")
		and not target_19.getTarget().hasName("sysfs_emit")
		and target_19.getArgument(0).(VariableAccess).getTarget()=vbuf_3604
		and target_19.getArgument(1).(StringLiteral).getValue()="%u\n"
		and target_19.getArgument(2).(PointerFieldAccess).getTarget().getName()="tcp_timestamp_en"
		and target_19.getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn_3606)
}

predicate func_20(Parameter vbuf_3604, Variable vconn_3606) {
	exists(FunctionCall target_20 |
		target_20.getTarget().hasName("sprintf")
		and not target_20.getTarget().hasName("sysfs_emit")
		and target_20.getArgument(0).(VariableAccess).getTarget()=vbuf_3604
		and target_20.getArgument(1).(StringLiteral).getValue()="%u\n"
		and target_20.getArgument(2).(PointerFieldAccess).getTarget().getName()="fragment_disable"
		and target_20.getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn_3606)
}

predicate func_21(Parameter vbuf_3604, Variable vconn_3606) {
	exists(FunctionCall target_21 |
		target_21.getTarget().hasName("sprintf")
		and not target_21.getTarget().hasName("sysfs_emit")
		and target_21.getArgument(0).(VariableAccess).getTarget()=vbuf_3604
		and target_21.getArgument(1).(StringLiteral).getValue()="%u\n"
		and target_21.getArgument(2).(PointerFieldAccess).getTarget().getName()="ipv4_tos"
		and target_21.getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn_3606)
}

predicate func_22(Parameter vbuf_3604, Variable vconn_3606) {
	exists(FunctionCall target_22 |
		target_22.getTarget().hasName("sprintf")
		and not target_22.getTarget().hasName("sysfs_emit")
		and target_22.getArgument(0).(VariableAccess).getTarget()=vbuf_3604
		and target_22.getArgument(1).(StringLiteral).getValue()="%u\n"
		and target_22.getArgument(2).(PointerFieldAccess).getTarget().getName()="ipv6_traffic_class"
		and target_22.getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn_3606)
}

predicate func_23(Parameter vbuf_3604, Variable vconn_3606) {
	exists(FunctionCall target_23 |
		target_23.getTarget().hasName("sprintf")
		and not target_23.getTarget().hasName("sysfs_emit")
		and target_23.getArgument(0).(VariableAccess).getTarget()=vbuf_3604
		and target_23.getArgument(1).(StringLiteral).getValue()="%u\n"
		and target_23.getArgument(2).(PointerFieldAccess).getTarget().getName()="ipv6_flow_label"
		and target_23.getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn_3606)
}

predicate func_24(Parameter vbuf_3604, Variable vconn_3606) {
	exists(FunctionCall target_24 |
		target_24.getTarget().hasName("sprintf")
		and not target_24.getTarget().hasName("sysfs_emit")
		and target_24.getArgument(0).(VariableAccess).getTarget()=vbuf_3604
		and target_24.getArgument(1).(StringLiteral).getValue()="%u\n"
		and target_24.getArgument(2).(PointerFieldAccess).getTarget().getName()="is_fw_assigned_ipv6"
		and target_24.getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn_3606)
}

predicate func_25(Parameter vbuf_3604, Variable vconn_3606) {
	exists(FunctionCall target_25 |
		target_25.getTarget().hasName("sprintf")
		and not target_25.getTarget().hasName("sysfs_emit")
		and target_25.getArgument(0).(VariableAccess).getTarget()=vbuf_3604
		and target_25.getArgument(1).(StringLiteral).getValue()="%u\n"
		and target_25.getArgument(2).(PointerFieldAccess).getTarget().getName()="tcp_xmit_wsf"
		and target_25.getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn_3606)
}

predicate func_26(Parameter vbuf_3604, Variable vconn_3606) {
	exists(FunctionCall target_26 |
		target_26.getTarget().hasName("sprintf")
		and not target_26.getTarget().hasName("sysfs_emit")
		and target_26.getArgument(0).(VariableAccess).getTarget()=vbuf_3604
		and target_26.getArgument(1).(StringLiteral).getValue()="%u\n"
		and target_26.getArgument(2).(PointerFieldAccess).getTarget().getName()="tcp_recv_wsf"
		and target_26.getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn_3606)
}

predicate func_27(Parameter vbuf_3604, Variable vconn_3606) {
	exists(FunctionCall target_27 |
		target_27.getTarget().hasName("sprintf")
		and not target_27.getTarget().hasName("sysfs_emit")
		and target_27.getArgument(0).(VariableAccess).getTarget()=vbuf_3604
		and target_27.getArgument(1).(StringLiteral).getValue()="%s\n"
		and target_27.getArgument(2).(PointerFieldAccess).getTarget().getName()="local_ipaddr"
		and target_27.getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn_3606)
}

from Function func, Parameter vbuf_3604, Variable vconn_3606
where
func_0(vbuf_3604, vconn_3606)
and func_1(vbuf_3604, vconn_3606)
and func_2(vbuf_3604, vconn_3606)
and func_3(vbuf_3604, vconn_3606)
and func_4(vbuf_3604, vconn_3606)
and func_5(vbuf_3604, vconn_3606)
and func_6(vbuf_3604, vconn_3606)
and func_7(vbuf_3604, vconn_3606)
and func_8(vbuf_3604, vconn_3606)
and func_9(vbuf_3604, vconn_3606)
and func_10(vbuf_3604, vconn_3606)
and func_11(vbuf_3604, vconn_3606)
and func_12(vbuf_3604, vconn_3606)
and func_13(vbuf_3604, vconn_3606)
and func_14(vbuf_3604, vconn_3606)
and func_15(vbuf_3604, vconn_3606)
and func_16(vbuf_3604, vconn_3606)
and func_17(vbuf_3604, vconn_3606)
and func_18(vbuf_3604, vconn_3606)
and func_19(vbuf_3604, vconn_3606)
and func_20(vbuf_3604, vconn_3606)
and func_21(vbuf_3604, vconn_3606)
and func_22(vbuf_3604, vconn_3606)
and func_23(vbuf_3604, vconn_3606)
and func_24(vbuf_3604, vconn_3606)
and func_25(vbuf_3604, vconn_3606)
and func_26(vbuf_3604, vconn_3606)
and func_27(vbuf_3604, vconn_3606)
and vbuf_3604.getType().hasName("char *")
and vconn_3606.getType().hasName("iscsi_conn *")
and vbuf_3604.getParentScope+() = func
and vconn_3606.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
