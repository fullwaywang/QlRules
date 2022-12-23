/**
 * @name linux-ec98ea7070e94cc25a422ec97d1421e28d97b7ee-iscsi_session_get_param
 * @id cpp/linux/ec98ea7070e94cc25a422ec97d1421e28d97b7ee/iscsi_session_get_param
 * @description linux-ec98ea7070e94cc25a422ec97d1421e28d97b7ee-iscsi_session_get_param 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Parameter vbuf_3426, Variable vsession_3428) {
	exists(FunctionCall target_0 |
		target_0.getTarget().hasName("sprintf")
		and not target_0.getTarget().hasName("sysfs_emit")
		and target_0.getArgument(0).(VariableAccess).getTarget()=vbuf_3426
		and target_0.getArgument(1).(StringLiteral).getValue()="%d\n"
		and target_0.getArgument(2).(PointerFieldAccess).getTarget().getName()="fast_abort"
		and target_0.getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsession_3428)
}

predicate func_1(Parameter vbuf_3426, Variable vsession_3428) {
	exists(FunctionCall target_1 |
		target_1.getTarget().hasName("sprintf")
		and not target_1.getTarget().hasName("sysfs_emit")
		and target_1.getArgument(0).(VariableAccess).getTarget()=vbuf_3426
		and target_1.getArgument(1).(StringLiteral).getValue()="%d\n"
		and target_1.getArgument(2).(PointerFieldAccess).getTarget().getName()="abort_timeout"
		and target_1.getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsession_3428)
}

predicate func_2(Parameter vbuf_3426, Variable vsession_3428) {
	exists(FunctionCall target_2 |
		target_2.getTarget().hasName("sprintf")
		and not target_2.getTarget().hasName("sysfs_emit")
		and target_2.getArgument(0).(VariableAccess).getTarget()=vbuf_3426
		and target_2.getArgument(1).(StringLiteral).getValue()="%d\n"
		and target_2.getArgument(2).(PointerFieldAccess).getTarget().getName()="lu_reset_timeout"
		and target_2.getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsession_3428)
}

predicate func_3(Parameter vbuf_3426, Variable vsession_3428) {
	exists(FunctionCall target_3 |
		target_3.getTarget().hasName("sprintf")
		and not target_3.getTarget().hasName("sysfs_emit")
		and target_3.getArgument(0).(VariableAccess).getTarget()=vbuf_3426
		and target_3.getArgument(1).(StringLiteral).getValue()="%d\n"
		and target_3.getArgument(2).(PointerFieldAccess).getTarget().getName()="tgt_reset_timeout"
		and target_3.getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsession_3428)
}

predicate func_4(Parameter vbuf_3426, Variable vsession_3428) {
	exists(FunctionCall target_4 |
		target_4.getTarget().hasName("sprintf")
		and not target_4.getTarget().hasName("sysfs_emit")
		and target_4.getArgument(0).(VariableAccess).getTarget()=vbuf_3426
		and target_4.getArgument(1).(StringLiteral).getValue()="%d\n"
		and target_4.getArgument(2).(PointerFieldAccess).getTarget().getName()="initial_r2t_en"
		and target_4.getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsession_3428)
}

predicate func_5(Parameter vbuf_3426, Variable vsession_3428) {
	exists(FunctionCall target_5 |
		target_5.getTarget().hasName("sprintf")
		and not target_5.getTarget().hasName("sysfs_emit")
		and target_5.getArgument(0).(VariableAccess).getTarget()=vbuf_3426
		and target_5.getArgument(1).(StringLiteral).getValue()="%hu\n"
		and target_5.getArgument(2).(PointerFieldAccess).getTarget().getName()="max_r2t"
		and target_5.getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsession_3428)
}

predicate func_6(Parameter vbuf_3426, Variable vsession_3428) {
	exists(FunctionCall target_6 |
		target_6.getTarget().hasName("sprintf")
		and not target_6.getTarget().hasName("sysfs_emit")
		and target_6.getArgument(0).(VariableAccess).getTarget()=vbuf_3426
		and target_6.getArgument(1).(StringLiteral).getValue()="%d\n"
		and target_6.getArgument(2).(PointerFieldAccess).getTarget().getName()="imm_data_en"
		and target_6.getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsession_3428)
}

predicate func_7(Parameter vbuf_3426, Variable vsession_3428) {
	exists(FunctionCall target_7 |
		target_7.getTarget().hasName("sprintf")
		and not target_7.getTarget().hasName("sysfs_emit")
		and target_7.getArgument(0).(VariableAccess).getTarget()=vbuf_3426
		and target_7.getArgument(1).(StringLiteral).getValue()="%u\n"
		and target_7.getArgument(2).(PointerFieldAccess).getTarget().getName()="first_burst"
		and target_7.getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsession_3428)
}

predicate func_8(Parameter vbuf_3426, Variable vsession_3428) {
	exists(FunctionCall target_8 |
		target_8.getTarget().hasName("sprintf")
		and not target_8.getTarget().hasName("sysfs_emit")
		and target_8.getArgument(0).(VariableAccess).getTarget()=vbuf_3426
		and target_8.getArgument(1).(StringLiteral).getValue()="%u\n"
		and target_8.getArgument(2).(PointerFieldAccess).getTarget().getName()="max_burst"
		and target_8.getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsession_3428)
}

predicate func_9(Parameter vbuf_3426, Variable vsession_3428) {
	exists(FunctionCall target_9 |
		target_9.getTarget().hasName("sprintf")
		and not target_9.getTarget().hasName("sysfs_emit")
		and target_9.getArgument(0).(VariableAccess).getTarget()=vbuf_3426
		and target_9.getArgument(1).(StringLiteral).getValue()="%d\n"
		and target_9.getArgument(2).(PointerFieldAccess).getTarget().getName()="pdu_inorder_en"
		and target_9.getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsession_3428)
}

predicate func_10(Parameter vbuf_3426, Variable vsession_3428) {
	exists(FunctionCall target_10 |
		target_10.getTarget().hasName("sprintf")
		and not target_10.getTarget().hasName("sysfs_emit")
		and target_10.getArgument(0).(VariableAccess).getTarget()=vbuf_3426
		and target_10.getArgument(1).(StringLiteral).getValue()="%d\n"
		and target_10.getArgument(2).(PointerFieldAccess).getTarget().getName()="dataseq_inorder_en"
		and target_10.getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsession_3428)
}

predicate func_11(Parameter vbuf_3426, Variable vsession_3428) {
	exists(FunctionCall target_11 |
		target_11.getTarget().hasName("sprintf")
		and not target_11.getTarget().hasName("sysfs_emit")
		and target_11.getArgument(0).(VariableAccess).getTarget()=vbuf_3426
		and target_11.getArgument(1).(StringLiteral).getValue()="%d\n"
		and target_11.getArgument(2).(PointerFieldAccess).getTarget().getName()="def_taskmgmt_tmo"
		and target_11.getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsession_3428)
}

predicate func_12(Parameter vbuf_3426, Variable vsession_3428) {
	exists(FunctionCall target_12 |
		target_12.getTarget().hasName("sprintf")
		and not target_12.getTarget().hasName("sysfs_emit")
		and target_12.getArgument(0).(VariableAccess).getTarget()=vbuf_3426
		and target_12.getArgument(1).(StringLiteral).getValue()="%d\n"
		and target_12.getArgument(2).(PointerFieldAccess).getTarget().getName()="erl"
		and target_12.getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsession_3428)
}

predicate func_13(Parameter vbuf_3426, Variable vsession_3428) {
	exists(FunctionCall target_13 |
		target_13.getTarget().hasName("sprintf")
		and not target_13.getTarget().hasName("sysfs_emit")
		and target_13.getArgument(0).(VariableAccess).getTarget()=vbuf_3426
		and target_13.getArgument(1).(StringLiteral).getValue()="%s\n"
		and target_13.getArgument(2).(PointerFieldAccess).getTarget().getName()="targetname"
		and target_13.getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsession_3428)
}

predicate func_14(Parameter vbuf_3426, Variable vsession_3428) {
	exists(FunctionCall target_14 |
		target_14.getTarget().hasName("sprintf")
		and not target_14.getTarget().hasName("sysfs_emit")
		and target_14.getArgument(0).(VariableAccess).getTarget()=vbuf_3426
		and target_14.getArgument(1).(StringLiteral).getValue()="%s\n"
		and target_14.getArgument(2).(PointerFieldAccess).getTarget().getName()="targetalias"
		and target_14.getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsession_3428)
}

predicate func_15(Parameter vbuf_3426, Variable vsession_3428) {
	exists(FunctionCall target_15 |
		target_15.getTarget().hasName("sprintf")
		and not target_15.getTarget().hasName("sysfs_emit")
		and target_15.getArgument(0).(VariableAccess).getTarget()=vbuf_3426
		and target_15.getArgument(1).(StringLiteral).getValue()="%d\n"
		and target_15.getArgument(2).(PointerFieldAccess).getTarget().getName()="tpgt"
		and target_15.getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsession_3428)
}

predicate func_16(Parameter vbuf_3426, Variable vsession_3428) {
	exists(FunctionCall target_16 |
		target_16.getTarget().hasName("sprintf")
		and not target_16.getTarget().hasName("sysfs_emit")
		and target_16.getArgument(0).(VariableAccess).getTarget()=vbuf_3426
		and target_16.getArgument(1).(StringLiteral).getValue()="%s\n"
		and target_16.getArgument(2).(PointerFieldAccess).getTarget().getName()="username"
		and target_16.getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsession_3428)
}

predicate func_17(Parameter vbuf_3426, Variable vsession_3428) {
	exists(FunctionCall target_17 |
		target_17.getTarget().hasName("sprintf")
		and not target_17.getTarget().hasName("sysfs_emit")
		and target_17.getArgument(0).(VariableAccess).getTarget()=vbuf_3426
		and target_17.getArgument(1).(StringLiteral).getValue()="%s\n"
		and target_17.getArgument(2).(PointerFieldAccess).getTarget().getName()="username_in"
		and target_17.getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsession_3428)
}

predicate func_18(Parameter vbuf_3426, Variable vsession_3428) {
	exists(FunctionCall target_18 |
		target_18.getTarget().hasName("sprintf")
		and not target_18.getTarget().hasName("sysfs_emit")
		and target_18.getArgument(0).(VariableAccess).getTarget()=vbuf_3426
		and target_18.getArgument(1).(StringLiteral).getValue()="%s\n"
		and target_18.getArgument(2).(PointerFieldAccess).getTarget().getName()="password"
		and target_18.getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsession_3428)
}

predicate func_19(Parameter vbuf_3426, Variable vsession_3428) {
	exists(FunctionCall target_19 |
		target_19.getTarget().hasName("sprintf")
		and not target_19.getTarget().hasName("sysfs_emit")
		and target_19.getArgument(0).(VariableAccess).getTarget()=vbuf_3426
		and target_19.getArgument(1).(StringLiteral).getValue()="%s\n"
		and target_19.getArgument(2).(PointerFieldAccess).getTarget().getName()="password_in"
		and target_19.getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsession_3428)
}

predicate func_20(Parameter vbuf_3426, Variable vsession_3428) {
	exists(FunctionCall target_20 |
		target_20.getTarget().hasName("sprintf")
		and not target_20.getTarget().hasName("sysfs_emit")
		and target_20.getArgument(0).(VariableAccess).getTarget()=vbuf_3426
		and target_20.getArgument(1).(StringLiteral).getValue()="%s\n"
		and target_20.getArgument(2).(PointerFieldAccess).getTarget().getName()="ifacename"
		and target_20.getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsession_3428)
}

predicate func_21(Parameter vbuf_3426, Variable vsession_3428) {
	exists(FunctionCall target_21 |
		target_21.getTarget().hasName("sprintf")
		and not target_21.getTarget().hasName("sysfs_emit")
		and target_21.getArgument(0).(VariableAccess).getTarget()=vbuf_3426
		and target_21.getArgument(1).(StringLiteral).getValue()="%s\n"
		and target_21.getArgument(2).(PointerFieldAccess).getTarget().getName()="initiatorname"
		and target_21.getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsession_3428)
}

predicate func_22(Parameter vbuf_3426, Variable vsession_3428) {
	exists(FunctionCall target_22 |
		target_22.getTarget().hasName("sprintf")
		and not target_22.getTarget().hasName("sysfs_emit")
		and target_22.getArgument(0).(VariableAccess).getTarget()=vbuf_3426
		and target_22.getArgument(1).(StringLiteral).getValue()="%s\n"
		and target_22.getArgument(2).(PointerFieldAccess).getTarget().getName()="boot_root"
		and target_22.getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsession_3428)
}

predicate func_23(Parameter vbuf_3426, Variable vsession_3428) {
	exists(FunctionCall target_23 |
		target_23.getTarget().hasName("sprintf")
		and not target_23.getTarget().hasName("sysfs_emit")
		and target_23.getArgument(0).(VariableAccess).getTarget()=vbuf_3426
		and target_23.getArgument(1).(StringLiteral).getValue()="%s\n"
		and target_23.getArgument(2).(PointerFieldAccess).getTarget().getName()="boot_nic"
		and target_23.getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsession_3428)
}

predicate func_24(Parameter vbuf_3426, Variable vsession_3428) {
	exists(FunctionCall target_24 |
		target_24.getTarget().hasName("sprintf")
		and not target_24.getTarget().hasName("sysfs_emit")
		and target_24.getArgument(0).(VariableAccess).getTarget()=vbuf_3426
		and target_24.getArgument(1).(StringLiteral).getValue()="%s\n"
		and target_24.getArgument(2).(PointerFieldAccess).getTarget().getName()="boot_target"
		and target_24.getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsession_3428)
}

predicate func_25(Parameter vbuf_3426, Variable vsession_3428) {
	exists(FunctionCall target_25 |
		target_25.getTarget().hasName("sprintf")
		and not target_25.getTarget().hasName("sysfs_emit")
		and target_25.getArgument(0).(VariableAccess).getTarget()=vbuf_3426
		and target_25.getArgument(1).(StringLiteral).getValue()="%u\n"
		and target_25.getArgument(2).(PointerFieldAccess).getTarget().getName()="auto_snd_tgt_disable"
		and target_25.getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsession_3428)
}

predicate func_26(Parameter vbuf_3426, Variable vsession_3428) {
	exists(FunctionCall target_26 |
		target_26.getTarget().hasName("sprintf")
		and not target_26.getTarget().hasName("sysfs_emit")
		and target_26.getArgument(0).(VariableAccess).getTarget()=vbuf_3426
		and target_26.getArgument(1).(StringLiteral).getValue()="%u\n"
		and target_26.getArgument(2).(PointerFieldAccess).getTarget().getName()="discovery_sess"
		and target_26.getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsession_3428)
}

predicate func_27(Parameter vbuf_3426, Variable vsession_3428) {
	exists(FunctionCall target_27 |
		target_27.getTarget().hasName("sprintf")
		and not target_27.getTarget().hasName("sysfs_emit")
		and target_27.getArgument(0).(VariableAccess).getTarget()=vbuf_3426
		and target_27.getArgument(1).(StringLiteral).getValue()="%s\n"
		and target_27.getArgument(2).(PointerFieldAccess).getTarget().getName()="portal_type"
		and target_27.getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsession_3428)
}

predicate func_28(Parameter vbuf_3426, Variable vsession_3428) {
	exists(FunctionCall target_28 |
		target_28.getTarget().hasName("sprintf")
		and not target_28.getTarget().hasName("sysfs_emit")
		and target_28.getArgument(0).(VariableAccess).getTarget()=vbuf_3426
		and target_28.getArgument(1).(StringLiteral).getValue()="%u\n"
		and target_28.getArgument(2).(PointerFieldAccess).getTarget().getName()="chap_auth_en"
		and target_28.getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsession_3428)
}

predicate func_29(Parameter vbuf_3426, Variable vsession_3428) {
	exists(FunctionCall target_29 |
		target_29.getTarget().hasName("sprintf")
		and not target_29.getTarget().hasName("sysfs_emit")
		and target_29.getArgument(0).(VariableAccess).getTarget()=vbuf_3426
		and target_29.getArgument(1).(StringLiteral).getValue()="%u\n"
		and target_29.getArgument(2).(PointerFieldAccess).getTarget().getName()="discovery_logout_en"
		and target_29.getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsession_3428)
}

predicate func_30(Parameter vbuf_3426, Variable vsession_3428) {
	exists(FunctionCall target_30 |
		target_30.getTarget().hasName("sprintf")
		and not target_30.getTarget().hasName("sysfs_emit")
		and target_30.getArgument(0).(VariableAccess).getTarget()=vbuf_3426
		and target_30.getArgument(1).(StringLiteral).getValue()="%u\n"
		and target_30.getArgument(2).(PointerFieldAccess).getTarget().getName()="bidi_chap_en"
		and target_30.getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsession_3428)
}

predicate func_31(Parameter vbuf_3426, Variable vsession_3428) {
	exists(FunctionCall target_31 |
		target_31.getTarget().hasName("sprintf")
		and not target_31.getTarget().hasName("sysfs_emit")
		and target_31.getArgument(0).(VariableAccess).getTarget()=vbuf_3426
		and target_31.getArgument(1).(StringLiteral).getValue()="%u\n"
		and target_31.getArgument(2).(PointerFieldAccess).getTarget().getName()="discovery_auth_optional"
		and target_31.getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsession_3428)
}

predicate func_32(Parameter vbuf_3426, Variable vsession_3428) {
	exists(FunctionCall target_32 |
		target_32.getTarget().hasName("sprintf")
		and not target_32.getTarget().hasName("sysfs_emit")
		and target_32.getArgument(0).(VariableAccess).getTarget()=vbuf_3426
		and target_32.getArgument(1).(StringLiteral).getValue()="%d\n"
		and target_32.getArgument(2).(PointerFieldAccess).getTarget().getName()="time2wait"
		and target_32.getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsession_3428)
}

predicate func_33(Parameter vbuf_3426, Variable vsession_3428) {
	exists(FunctionCall target_33 |
		target_33.getTarget().hasName("sprintf")
		and not target_33.getTarget().hasName("sysfs_emit")
		and target_33.getArgument(0).(VariableAccess).getTarget()=vbuf_3426
		and target_33.getArgument(1).(StringLiteral).getValue()="%d\n"
		and target_33.getArgument(2).(PointerFieldAccess).getTarget().getName()="time2retain"
		and target_33.getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsession_3428)
}

predicate func_34(Parameter vbuf_3426, Variable vsession_3428) {
	exists(FunctionCall target_34 |
		target_34.getTarget().hasName("sprintf")
		and not target_34.getTarget().hasName("sysfs_emit")
		and target_34.getArgument(0).(VariableAccess).getTarget()=vbuf_3426
		and target_34.getArgument(1).(StringLiteral).getValue()="%u\n"
		and target_34.getArgument(2).(PointerFieldAccess).getTarget().getName()="tsid"
		and target_34.getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsession_3428)
}

predicate func_35(Parameter vbuf_3426, Variable vsession_3428) {
	exists(FunctionCall target_35 |
		target_35.getTarget().hasName("sprintf")
		and not target_35.getTarget().hasName("sysfs_emit")
		and target_35.getArgument(0).(VariableAccess).getTarget()=vbuf_3426
		and target_35.getArgument(1).(StringLiteral).getValue()="%02x%02x%02x%02x%02x%02x\n"
		and target_35.getArgument(2).(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="isid"
		and target_35.getArgument(2).(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsession_3428
		and target_35.getArgument(2).(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_35.getArgument(3).(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="isid"
		and target_35.getArgument(3).(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsession_3428
		and target_35.getArgument(3).(ArrayExpr).getArrayOffset().(Literal).getValue()="1"
		and target_35.getArgument(4).(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="isid"
		and target_35.getArgument(4).(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsession_3428
		and target_35.getArgument(4).(ArrayExpr).getArrayOffset().(Literal).getValue()="2"
		and target_35.getArgument(5).(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="isid"
		and target_35.getArgument(5).(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsession_3428
		and target_35.getArgument(5).(ArrayExpr).getArrayOffset().(Literal).getValue()="3"
		and target_35.getArgument(6).(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="isid"
		and target_35.getArgument(6).(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsession_3428
		and target_35.getArgument(6).(ArrayExpr).getArrayOffset().(Literal).getValue()="4"
		and target_35.getArgument(7).(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="isid"
		and target_35.getArgument(7).(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsession_3428
		and target_35.getArgument(7).(ArrayExpr).getArrayOffset().(Literal).getValue()="5")
}

predicate func_36(Parameter vbuf_3426, Variable vsession_3428) {
	exists(FunctionCall target_36 |
		target_36.getTarget().hasName("sprintf")
		and not target_36.getTarget().hasName("sysfs_emit")
		and target_36.getArgument(0).(VariableAccess).getTarget()=vbuf_3426
		and target_36.getArgument(1).(StringLiteral).getValue()="%u\n"
		and target_36.getArgument(2).(PointerFieldAccess).getTarget().getName()="discovery_parent_idx"
		and target_36.getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsession_3428)
}

predicate func_37(Parameter vbuf_3426, Variable vsession_3428) {
	exists(FunctionCall target_37 |
		target_37.getTarget().hasName("sprintf")
		and not target_37.getTarget().hasName("sysfs_emit")
		and target_37.getArgument(0).(VariableAccess).getTarget()=vbuf_3426
		and target_37.getArgument(1).(StringLiteral).getValue()="%s\n"
		and target_37.getArgument(2).(PointerFieldAccess).getTarget().getName()="discovery_parent_type"
		and target_37.getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsession_3428)
}

predicate func_38(Parameter vbuf_3426) {
	exists(FunctionCall target_38 |
		target_38.getTarget().hasName("sprintf")
		and not target_38.getTarget().hasName("sysfs_emit")
		and target_38.getArgument(0).(VariableAccess).getTarget()=vbuf_3426
		and target_38.getArgument(1).(StringLiteral).getValue()="\n")
}

from Function func, Parameter vbuf_3426, Variable vsession_3428
where
func_0(vbuf_3426, vsession_3428)
and func_1(vbuf_3426, vsession_3428)
and func_2(vbuf_3426, vsession_3428)
and func_3(vbuf_3426, vsession_3428)
and func_4(vbuf_3426, vsession_3428)
and func_5(vbuf_3426, vsession_3428)
and func_6(vbuf_3426, vsession_3428)
and func_7(vbuf_3426, vsession_3428)
and func_8(vbuf_3426, vsession_3428)
and func_9(vbuf_3426, vsession_3428)
and func_10(vbuf_3426, vsession_3428)
and func_11(vbuf_3426, vsession_3428)
and func_12(vbuf_3426, vsession_3428)
and func_13(vbuf_3426, vsession_3428)
and func_14(vbuf_3426, vsession_3428)
and func_15(vbuf_3426, vsession_3428)
and func_16(vbuf_3426, vsession_3428)
and func_17(vbuf_3426, vsession_3428)
and func_18(vbuf_3426, vsession_3428)
and func_19(vbuf_3426, vsession_3428)
and func_20(vbuf_3426, vsession_3428)
and func_21(vbuf_3426, vsession_3428)
and func_22(vbuf_3426, vsession_3428)
and func_23(vbuf_3426, vsession_3428)
and func_24(vbuf_3426, vsession_3428)
and func_25(vbuf_3426, vsession_3428)
and func_26(vbuf_3426, vsession_3428)
and func_27(vbuf_3426, vsession_3428)
and func_28(vbuf_3426, vsession_3428)
and func_29(vbuf_3426, vsession_3428)
and func_30(vbuf_3426, vsession_3428)
and func_31(vbuf_3426, vsession_3428)
and func_32(vbuf_3426, vsession_3428)
and func_33(vbuf_3426, vsession_3428)
and func_34(vbuf_3426, vsession_3428)
and func_35(vbuf_3426, vsession_3428)
and func_36(vbuf_3426, vsession_3428)
and func_37(vbuf_3426, vsession_3428)
and func_38(vbuf_3426)
and vbuf_3426.getType().hasName("char *")
and vsession_3428.getType().hasName("iscsi_session *")
and vbuf_3426.getParentScope+() = func
and vsession_3428.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
