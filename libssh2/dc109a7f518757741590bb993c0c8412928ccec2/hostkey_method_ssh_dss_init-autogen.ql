/**
 * @name libssh2-dc109a7f518757741590bb993c0c8412928ccec2-hostkey_method_ssh_dss_init
 * @id cpp/libssh2/dc109a7f518757741590bb993c0c8412928ccec2/hostkey-method-ssh-dss-init
 * @description libssh2-dc109a7f518757741590bb993c0c8412928ccec2-src/hostkey.c-hostkey_method_ssh_dss_init CVE-2019-3859
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func, Literal target_0) {
		target_0.getValue()="4"
		and not target_0.getValue()="0"
		and target_0.getParent().(AssignPointerAddExpr).getParent().(ExprStmt).getExpr() instanceof AssignPointerAddExpr
		and target_0.getEnclosingFunction() = func
}

predicate func_1(Variable vlen_285, ExprStmt target_71, Literal target_1) {
		target_1.getValue()="7"
		and not target_1.getValue()="0"
		and target_1.getParent().(NEExpr).getParent().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vlen_285
		and target_71.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_1.getParent().(NEExpr).getParent().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getLocation())
}

predicate func_2(Variable vs_284, FunctionCall target_2) {
		target_2.getTarget().hasName("strncmp")
		and not target_2.getTarget().hasName("_libssh2_match_string")
		and target_2.getArgument(0).(VariableAccess).getTarget()=vs_284
		and target_2.getArgument(1).(StringLiteral).getValue()="ssh-dss"
		and target_2.getArgument(2).(Literal).getValue()="7"
}

predicate func_3(Function func, Literal target_3) {
		target_3.getValue()="7"
		and not target_3.getValue()="0"
		and target_3.getParent().(AssignPointerAddExpr).getParent().(ExprStmt).getExpr() instanceof AssignPointerAddExpr
		and target_3.getEnclosingFunction() = func
}

predicate func_4(Function func, Literal target_4) {
		target_4.getValue()="4"
		and not target_4.getValue()="1"
		and target_4.getParent().(AssignPointerAddExpr).getParent().(ExprStmt).getExpr() instanceof AssignPointerAddExpr
		and target_4.getEnclosingFunction() = func
}

predicate func_5(Function func, Literal target_5) {
		target_5.getValue()="4"
		and not target_5.getValue()="0"
		and target_5.getParent().(AssignPointerAddExpr).getParent().(ExprStmt).getExpr() instanceof AssignPointerAddExpr
		and target_5.getEnclosingFunction() = func
}

predicate func_6(Function func, Literal target_6) {
		target_6.getValue()="4"
		and not target_6.getValue()="1"
		and target_6.getParent().(AssignPointerAddExpr).getParent().(ExprStmt).getExpr() instanceof AssignPointerAddExpr
		and target_6.getEnclosingFunction() = func
}

predicate func_7(Function func, Literal target_7) {
		target_7.getValue()="4"
		and not target_7.getValue()="0"
		and target_7.getParent().(AssignPointerAddExpr).getParent().(ExprStmt).getExpr() instanceof AssignPointerAddExpr
		and target_7.getEnclosingFunction() = func
}

predicate func_13(Parameter vhostkey_data_len_280, BlockStmt target_72) {
	exists(RelationalOperation target_13 |
		 (target_13 instanceof GTExpr or target_13 instanceof LTExpr)
		and target_13.getLesserOperand().(VariableAccess).getTarget()=vhostkey_data_len_280
		and target_13.getGreaterOperand().(Literal).getValue()="27"
		and target_13.getParent().(IfStmt).getThen()=target_72)
}

predicate func_14(VariableAccess target_70, Function func) {
	exists(DoStmt target_14 |
		target_14.getCondition().(Literal).getValue()="0"
		and target_14.getStmt().(BlockStmt).toString() = "{ ... }"
		and target_14.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0)=target_14
		and target_14.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_70
		and target_14.getEnclosingFunction() = func)
}

predicate func_15(Parameter vhostkey_data_279) {
	exists(AssignExpr target_15 |
		target_15.getLValue().(ValueFieldAccess).getTarget().getName()="data"
		and target_15.getLValue().(ValueFieldAccess).getQualifier().(VariableAccess).getType().hasName("string_buf")
		and target_15.getRValue().(VariableAccess).getTarget()=vhostkey_data_279)
}

predicate func_16(Function func) {
	exists(AssignExpr target_16 |
		target_16.getLValue().(ValueFieldAccess).getTarget().getName()="dataptr"
		and target_16.getLValue().(ValueFieldAccess).getQualifier().(VariableAccess).getType().hasName("string_buf")
		and target_16.getRValue().(ValueFieldAccess).getTarget().getName()="data"
		and target_16.getRValue().(ValueFieldAccess).getQualifier().(VariableAccess).getType().hasName("string_buf")
		and target_16.getEnclosingFunction() = func)
}

predicate func_17(Parameter vhostkey_data_len_280, ExprStmt target_73) {
	exists(AssignExpr target_17 |
		target_17.getLValue().(ValueFieldAccess).getTarget().getName()="len"
		and target_17.getLValue().(ValueFieldAccess).getQualifier().(VariableAccess).getType().hasName("string_buf")
		and target_17.getRValue().(VariableAccess).getTarget()=vhostkey_data_len_280
		and target_73.getExpr().(VariableAccess).getLocation().isBefore(target_17.getRValue().(VariableAccess).getLocation()))
}

predicate func_18(Function func) {
	exists(AddressOfExpr target_18 |
		target_18.getOperand().(VariableAccess).getType().hasName("string_buf")
		and target_18.getParent().(FunctionCall).getParent().(NEExpr).getAnOperand() instanceof FunctionCall
		and target_18.getEnclosingFunction() = func)
}

predicate func_19(VariableAccess target_70, Function func) {
	exists(ReturnStmt target_19 |
		target_19.getExpr().(UnaryMinusExpr).getValue()="-1"
		and target_19.getParent().(IfStmt).getCondition()=target_70
		and target_19.getEnclosingFunction() = func)
}

predicate func_20(Variable vp_1_284, Variable vp_len_285, ExprStmt target_55, Function func) {
	exists(IfStmt target_20 |
		target_20.getCondition().(RelationalOperation).getLesserOperand().(AssignExpr).getLValue().(VariableAccess).getTarget()=vp_len_285
		and target_20.getCondition().(RelationalOperation).getLesserOperand().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("_libssh2_get_c_string")
		and target_20.getCondition().(RelationalOperation).getLesserOperand().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getType().hasName("string_buf")
		and target_20.getCondition().(RelationalOperation).getLesserOperand().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vp_1_284
		and target_20.getCondition().(RelationalOperation).getGreaterOperand().(Literal).getValue()="0"
		and target_20.getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-1"
		and (func.getEntryPoint().(BlockStmt).getStmt(10)=target_20 or func.getEntryPoint().(BlockStmt).getStmt(10).getFollowingStmt()=target_20)
		and target_20.getCondition().(RelationalOperation).getLesserOperand().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_55.getExpr().(AssignPointerAddExpr).getRValue().(VariableAccess).getLocation()))
}

/*predicate func_21(Variable vp_1_284) {
	exists(FunctionCall target_21 |
		target_21.getTarget().hasName("_libssh2_get_c_string")
		and target_21.getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getType().hasName("string_buf")
		and target_21.getArgument(1).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vp_1_284)
}

*/
predicate func_22(Variable vq_1_284, Variable vq_len_285, ExprStmt target_60, Function func) {
	exists(IfStmt target_22 |
		target_22.getCondition().(RelationalOperation).getLesserOperand().(AssignExpr).getLValue().(VariableAccess).getTarget()=vq_len_285
		and target_22.getCondition().(RelationalOperation).getLesserOperand().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("_libssh2_get_c_string")
		and target_22.getCondition().(RelationalOperation).getLesserOperand().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getType().hasName("string_buf")
		and target_22.getCondition().(RelationalOperation).getLesserOperand().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vq_1_284
		and target_22.getCondition().(RelationalOperation).getGreaterOperand().(Literal).getValue()="0"
		and target_22.getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-1"
		and (func.getEntryPoint().(BlockStmt).getStmt(11)=target_22 or func.getEntryPoint().(BlockStmt).getStmt(11).getFollowingStmt()=target_22)
		and target_22.getCondition().(RelationalOperation).getLesserOperand().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_60.getExpr().(AssignPointerAddExpr).getRValue().(VariableAccess).getLocation()))
}

/*predicate func_23(Variable vq_1_284) {
	exists(FunctionCall target_23 |
		target_23.getTarget().hasName("_libssh2_get_c_string")
		and target_23.getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getType().hasName("string_buf")
		and target_23.getArgument(1).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vq_1_284)
}

*/
predicate func_24(Variable vg_1_284, Variable vg_len_285, ExprStmt target_65, Function func) {
	exists(IfStmt target_24 |
		target_24.getCondition().(RelationalOperation).getLesserOperand().(AssignExpr).getLValue().(VariableAccess).getTarget()=vg_len_285
		and target_24.getCondition().(RelationalOperation).getLesserOperand().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("_libssh2_get_c_string")
		and target_24.getCondition().(RelationalOperation).getLesserOperand().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getType().hasName("string_buf")
		and target_24.getCondition().(RelationalOperation).getLesserOperand().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vg_1_284
		and target_24.getCondition().(RelationalOperation).getGreaterOperand().(Literal).getValue()="0"
		and target_24.getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-1"
		and (func.getEntryPoint().(BlockStmt).getStmt(12)=target_24 or func.getEntryPoint().(BlockStmt).getStmt(12).getFollowingStmt()=target_24)
		and target_24.getCondition().(RelationalOperation).getLesserOperand().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_65.getExpr().(AssignPointerAddExpr).getRValue().(VariableAccess).getLocation()))
}

/*predicate func_25(Variable vg_1_284) {
	exists(FunctionCall target_25 |
		target_25.getTarget().hasName("_libssh2_get_c_string")
		and target_25.getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getType().hasName("string_buf")
		and target_25.getArgument(1).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vg_1_284)
}

*/
predicate func_26(Variable vy_1_284, Variable vy_len_285, ExprStmt target_69, Function func) {
	exists(IfStmt target_26 |
		target_26.getCondition().(RelationalOperation).getLesserOperand().(AssignExpr).getLValue().(VariableAccess).getTarget()=vy_len_285
		and target_26.getCondition().(RelationalOperation).getLesserOperand().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("_libssh2_get_c_string")
		and target_26.getCondition().(RelationalOperation).getLesserOperand().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getType().hasName("string_buf")
		and target_26.getCondition().(RelationalOperation).getLesserOperand().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vy_1_284
		and target_26.getCondition().(RelationalOperation).getGreaterOperand().(Literal).getValue()="0"
		and target_26.getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-1"
		and (func.getEntryPoint().(BlockStmt).getStmt(13)=target_26 or func.getEntryPoint().(BlockStmt).getStmt(13).getFollowingStmt()=target_26))
}

/*predicate func_27(Variable vy_1_284) {
	exists(FunctionCall target_27 |
		target_27.getTarget().hasName("_libssh2_get_c_string")
		and target_27.getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getType().hasName("string_buf")
		and target_27.getArgument(1).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vy_1_284)
}

*/
predicate func_28(Function func) {
	exists(IfStmt target_28 |
		target_28.getCondition() instanceof FunctionCall
		and target_28.getThen().(BlockStmt).getStmt(0).(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-1"
		and (func.getEntryPoint().(BlockStmt).getStmt(14)=target_28 or func.getEntryPoint().(BlockStmt).getStmt(14).getFollowingStmt()=target_28))
}

predicate func_29(Variable vdsactx_283, Variable vp_1_284, Variable vq_1_284, Variable vg_1_284, Variable vy_1_284, Variable vp_len_285, Variable vq_len_285, Variable vg_len_285, Variable vy_len_285, FunctionCall target_29) {
		target_29.getTarget().hasName("_libssh2_dsa_new")
		and target_29.getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vdsactx_283
		and target_29.getArgument(1).(VariableAccess).getTarget()=vp_1_284
		and target_29.getArgument(2).(VariableAccess).getTarget()=vp_len_285
		and target_29.getArgument(3).(VariableAccess).getTarget()=vq_1_284
		and target_29.getArgument(4).(VariableAccess).getTarget()=vq_len_285
		and target_29.getArgument(5).(VariableAccess).getTarget()=vg_1_284
		and target_29.getArgument(6).(VariableAccess).getTarget()=vg_len_285
		and target_29.getArgument(7).(VariableAccess).getTarget()=vy_1_284
		and target_29.getArgument(8).(VariableAccess).getTarget()=vy_len_285
		and target_29.getArgument(9).(Literal).getValue()="0"
		and target_29.getArgument(10).(Literal).getValue()="0"
}

predicate func_30(Parameter vhostkey_data_279, Variable vs_284, VariableAccess target_30) {
		target_30.getTarget()=vhostkey_data_279
		and target_30.getParent().(AssignExpr).getRValue() = target_30
		and target_30.getParent().(AssignExpr).getLValue().(VariableAccess).getTarget()=vs_284
}

predicate func_32(Variable vp_len_285, VariableAccess target_32) {
		target_32.getTarget()=vp_len_285
		and target_32.getParent().(AssignExpr).getLValue() = target_32
		and target_32.getParent().(AssignExpr).getRValue() instanceof FunctionCall
}

predicate func_33(Variable vq_len_285, VariableAccess target_33) {
		target_33.getTarget()=vq_len_285
		and target_33.getParent().(AssignExpr).getLValue() = target_33
		and target_33.getParent().(AssignExpr).getRValue() instanceof FunctionCall
}

predicate func_34(Variable vg_len_285, VariableAccess target_34) {
		target_34.getTarget()=vg_len_285
		and target_34.getParent().(AssignExpr).getLValue() = target_34
		and target_34.getParent().(AssignExpr).getRValue() instanceof FunctionCall
}

predicate func_35(Variable vy_len_285, VariableAccess target_35) {
		target_35.getTarget()=vy_len_285
		and target_35.getParent().(AssignExpr).getLValue() = target_35
		and target_35.getParent().(AssignExpr).getRValue() instanceof FunctionCall
}

predicate func_36(Parameter vhostkey_data_len_280, VariableAccess target_36) {
		target_36.getTarget()=vhostkey_data_len_280
}

predicate func_44(Parameter vhostkey_data_279, Variable vs_284, AssignExpr target_44) {
		target_44.getLValue().(VariableAccess).getTarget()=vs_284
		and target_44.getRValue().(VariableAccess).getTarget()=vhostkey_data_279
}

predicate func_45(Variable vs_284, Variable vlen_285, VariableAccess target_45) {
		target_45.getTarget()=vlen_285
		and target_45.getParent().(AssignExpr).getLValue() = target_45
		and target_45.getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("_libssh2_ntohu32")
		and target_45.getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs_284
}

/*predicate func_46(Variable vs_284, ExprStmt target_47, FunctionCall target_46) {
		target_46.getTarget().hasName("_libssh2_ntohu32")
		and target_46.getArgument(0).(VariableAccess).getTarget()=vs_284
		and target_46.getArgument(0).(VariableAccess).getLocation().isBefore(target_47.getExpr().(AssignPointerAddExpr).getLValue().(VariableAccess).getLocation())
}

*/
predicate func_47(Variable vs_284, ExprStmt target_71, LogicalOrExpr target_48, Function func, ExprStmt target_47) {
		target_47.getExpr().(AssignPointerAddExpr).getLValue().(VariableAccess).getTarget()=vs_284
		and target_47.getExpr().(AssignPointerAddExpr).getRValue() instanceof Literal
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_47
}

predicate func_48(Variable vlen_285, BlockStmt target_72, LogicalOrExpr target_48) {
		target_48.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vlen_285
		and target_48.getAnOperand().(EqualityOperation).getAnOperand() instanceof Literal
		and target_48.getAnOperand().(EqualityOperation).getAnOperand() instanceof FunctionCall
		and target_48.getAnOperand().(EqualityOperation).getAnOperand() instanceof Literal
		and target_48.getParent().(IfStmt).getThen()=target_72
}

/*predicate func_49(Variable vlen_285, VariableAccess target_49) {
		target_49.getTarget()=vlen_285
}

*/
predicate func_50(Variable vs_284, Function func, ExprStmt target_50) {
		target_50.getExpr().(AssignPointerAddExpr).getLValue().(VariableAccess).getTarget()=vs_284
		and target_50.getExpr().(AssignPointerAddExpr).getRValue() instanceof Literal
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_50
}

predicate func_51(Variable vs_284, Variable vp_len_285, Function func, ExprStmt target_51) {
		target_51.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vp_len_285
		and target_51.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("_libssh2_ntohu32")
		and target_51.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs_284
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_51
}

/*predicate func_52(Variable vs_284, ExprStmt target_50, ExprStmt target_53, FunctionCall target_52) {
		target_52.getTarget().hasName("_libssh2_ntohu32")
		and target_52.getArgument(0).(VariableAccess).getTarget()=vs_284
		and target_50.getExpr().(AssignPointerAddExpr).getLValue().(VariableAccess).getLocation().isBefore(target_52.getArgument(0).(VariableAccess).getLocation())
		and target_52.getArgument(0).(VariableAccess).getLocation().isBefore(target_53.getExpr().(AssignPointerAddExpr).getLValue().(VariableAccess).getLocation())
}

*/
predicate func_53(Variable vs_284, ExprStmt target_51, ExprStmt target_54, Function func, ExprStmt target_53) {
		target_53.getExpr().(AssignPointerAddExpr).getLValue().(VariableAccess).getTarget()=vs_284
		and target_53.getExpr().(AssignPointerAddExpr).getRValue() instanceof Literal
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_53
		and target_51.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_53.getExpr().(AssignPointerAddExpr).getLValue().(VariableAccess).getLocation())
		and target_53.getExpr().(AssignPointerAddExpr).getLValue().(VariableAccess).getLocation().isBefore(target_54.getExpr().(AssignExpr).getRValue().(VariableAccess).getLocation())
}

predicate func_54(Variable vp_1_284, Variable vs_284, Function func, ExprStmt target_54) {
		target_54.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vp_1_284
		and target_54.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vs_284
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_54
}

predicate func_55(Variable vs_284, Variable vp_len_285, Function func, ExprStmt target_55) {
		target_55.getExpr().(AssignPointerAddExpr).getLValue().(VariableAccess).getTarget()=vs_284
		and target_55.getExpr().(AssignPointerAddExpr).getRValue().(VariableAccess).getTarget()=vp_len_285
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_55
}

predicate func_56(Variable vs_284, Variable vq_len_285, Function func, ExprStmt target_56) {
		target_56.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vq_len_285
		and target_56.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("_libssh2_ntohu32")
		and target_56.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs_284
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_56
}

/*predicate func_57(Variable vs_284, ExprStmt target_55, ExprStmt target_58, FunctionCall target_57) {
		target_57.getTarget().hasName("_libssh2_ntohu32")
		and target_57.getArgument(0).(VariableAccess).getTarget()=vs_284
		and target_55.getExpr().(AssignPointerAddExpr).getLValue().(VariableAccess).getLocation().isBefore(target_57.getArgument(0).(VariableAccess).getLocation())
		and target_57.getArgument(0).(VariableAccess).getLocation().isBefore(target_58.getExpr().(AssignPointerAddExpr).getLValue().(VariableAccess).getLocation())
}

*/
predicate func_58(Variable vs_284, ExprStmt target_56, ExprStmt target_59, Function func, ExprStmt target_58) {
		target_58.getExpr().(AssignPointerAddExpr).getLValue().(VariableAccess).getTarget()=vs_284
		and target_58.getExpr().(AssignPointerAddExpr).getRValue() instanceof Literal
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_58
		and target_56.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_58.getExpr().(AssignPointerAddExpr).getLValue().(VariableAccess).getLocation())
		and target_58.getExpr().(AssignPointerAddExpr).getLValue().(VariableAccess).getLocation().isBefore(target_59.getExpr().(AssignExpr).getRValue().(VariableAccess).getLocation())
}

predicate func_59(Variable vq_1_284, Variable vs_284, Function func, ExprStmt target_59) {
		target_59.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vq_1_284
		and target_59.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vs_284
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_59
}

predicate func_60(Variable vs_284, Variable vq_len_285, Function func, ExprStmt target_60) {
		target_60.getExpr().(AssignPointerAddExpr).getLValue().(VariableAccess).getTarget()=vs_284
		and target_60.getExpr().(AssignPointerAddExpr).getRValue().(VariableAccess).getTarget()=vq_len_285
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_60
}

predicate func_61(Variable vs_284, Variable vg_len_285, Function func, ExprStmt target_61) {
		target_61.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vg_len_285
		and target_61.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("_libssh2_ntohu32")
		and target_61.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs_284
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_61
}

/*predicate func_62(Variable vs_284, ExprStmt target_60, ExprStmt target_63, FunctionCall target_62) {
		target_62.getTarget().hasName("_libssh2_ntohu32")
		and target_62.getArgument(0).(VariableAccess).getTarget()=vs_284
		and target_60.getExpr().(AssignPointerAddExpr).getLValue().(VariableAccess).getLocation().isBefore(target_62.getArgument(0).(VariableAccess).getLocation())
		and target_62.getArgument(0).(VariableAccess).getLocation().isBefore(target_63.getExpr().(AssignPointerAddExpr).getLValue().(VariableAccess).getLocation())
}

*/
predicate func_63(Variable vs_284, ExprStmt target_61, ExprStmt target_64, Function func, ExprStmt target_63) {
		target_63.getExpr().(AssignPointerAddExpr).getLValue().(VariableAccess).getTarget()=vs_284
		and target_63.getExpr().(AssignPointerAddExpr).getRValue() instanceof Literal
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_63
		and target_61.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_63.getExpr().(AssignPointerAddExpr).getLValue().(VariableAccess).getLocation())
		and target_63.getExpr().(AssignPointerAddExpr).getLValue().(VariableAccess).getLocation().isBefore(target_64.getExpr().(AssignExpr).getRValue().(VariableAccess).getLocation())
}

predicate func_64(Variable vg_1_284, Variable vs_284, Function func, ExprStmt target_64) {
		target_64.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vg_1_284
		and target_64.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vs_284
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_64
}

predicate func_65(Variable vs_284, Variable vg_len_285, Function func, ExprStmt target_65) {
		target_65.getExpr().(AssignPointerAddExpr).getLValue().(VariableAccess).getTarget()=vs_284
		and target_65.getExpr().(AssignPointerAddExpr).getRValue().(VariableAccess).getTarget()=vg_len_285
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_65
}

predicate func_66(Variable vs_284, Variable vy_len_285, Function func, ExprStmt target_66) {
		target_66.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vy_len_285
		and target_66.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("_libssh2_ntohu32")
		and target_66.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs_284
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_66
}

predicate func_67(Variable vs_284, ExprStmt target_66, ExprStmt target_68, Function func, ExprStmt target_67) {
		target_67.getExpr().(AssignPointerAddExpr).getLValue().(VariableAccess).getTarget()=vs_284
		and target_67.getExpr().(AssignPointerAddExpr).getRValue() instanceof Literal
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_67
		and target_66.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_67.getExpr().(AssignPointerAddExpr).getLValue().(VariableAccess).getLocation())
		and target_67.getExpr().(AssignPointerAddExpr).getLValue().(VariableAccess).getLocation().isBefore(target_68.getExpr().(AssignExpr).getRValue().(VariableAccess).getLocation())
}

predicate func_68(Variable vy_1_284, Variable vs_284, Function func, ExprStmt target_68) {
		target_68.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vy_1_284
		and target_68.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vs_284
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_68
}

predicate func_69(Variable vret_286, Function func, ExprStmt target_69) {
		target_69.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vret_286
		and target_69.getExpr().(AssignExpr).getRValue() instanceof FunctionCall
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_69
}

predicate func_70(Variable vret_286, BlockStmt target_75, VariableAccess target_70) {
		target_70.getTarget()=vret_286
		and target_70.getParent().(IfStmt).getThen()=target_75
}

predicate func_71(Variable vlen_285, ExprStmt target_71) {
		target_71.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vlen_285
		and target_71.getExpr().(AssignExpr).getRValue() instanceof FunctionCall
}

predicate func_72(BlockStmt target_72) {
		target_72.getStmt(0).(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-1"
}

predicate func_73(Parameter vhostkey_data_len_280, ExprStmt target_73) {
		target_73.getExpr().(VariableAccess).getTarget()=vhostkey_data_len_280
}

predicate func_75(BlockStmt target_75) {
		target_75.getStmt(0).(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-1"
}

from Function func, Parameter vhostkey_data_279, Parameter vhostkey_data_len_280, Variable vdsactx_283, Variable vp_1_284, Variable vq_1_284, Variable vg_1_284, Variable vy_1_284, Variable vs_284, Variable vp_len_285, Variable vq_len_285, Variable vg_len_285, Variable vy_len_285, Variable vlen_285, Variable vret_286, Literal target_0, Literal target_1, FunctionCall target_2, Literal target_3, Literal target_4, Literal target_5, Literal target_6, Literal target_7, FunctionCall target_29, VariableAccess target_30, VariableAccess target_32, VariableAccess target_33, VariableAccess target_34, VariableAccess target_35, VariableAccess target_36, AssignExpr target_44, VariableAccess target_45, ExprStmt target_47, LogicalOrExpr target_48, ExprStmt target_50, ExprStmt target_51, ExprStmt target_53, ExprStmt target_54, ExprStmt target_55, ExprStmt target_56, ExprStmt target_58, ExprStmt target_59, ExprStmt target_60, ExprStmt target_61, ExprStmt target_63, ExprStmt target_64, ExprStmt target_65, ExprStmt target_66, ExprStmt target_67, ExprStmt target_68, ExprStmt target_69, VariableAccess target_70, ExprStmt target_71, BlockStmt target_72, ExprStmt target_73, BlockStmt target_75
where
func_0(func, target_0)
and func_1(vlen_285, target_71, target_1)
and func_2(vs_284, target_2)
and func_3(func, target_3)
and func_4(func, target_4)
and func_5(func, target_5)
and func_6(func, target_6)
and func_7(func, target_7)
and not func_13(vhostkey_data_len_280, target_72)
and not func_14(target_70, func)
and not func_15(vhostkey_data_279)
and not func_16(func)
and not func_17(vhostkey_data_len_280, target_73)
and not func_18(func)
and not func_19(target_70, func)
and not func_20(vp_1_284, vp_len_285, target_55, func)
and not func_22(vq_1_284, vq_len_285, target_60, func)
and not func_24(vg_1_284, vg_len_285, target_65, func)
and not func_26(vy_1_284, vy_len_285, target_69, func)
and not func_28(func)
and func_29(vdsactx_283, vp_1_284, vq_1_284, vg_1_284, vy_1_284, vp_len_285, vq_len_285, vg_len_285, vy_len_285, target_29)
and func_30(vhostkey_data_279, vs_284, target_30)
and func_32(vp_len_285, target_32)
and func_33(vq_len_285, target_33)
and func_34(vg_len_285, target_34)
and func_35(vy_len_285, target_35)
and func_36(vhostkey_data_len_280, target_36)
and func_44(vhostkey_data_279, vs_284, target_44)
and func_45(vs_284, vlen_285, target_45)
and func_47(vs_284, target_71, target_48, func, target_47)
and func_48(vlen_285, target_72, target_48)
and func_50(vs_284, func, target_50)
and func_51(vs_284, vp_len_285, func, target_51)
and func_53(vs_284, target_51, target_54, func, target_53)
and func_54(vp_1_284, vs_284, func, target_54)
and func_55(vs_284, vp_len_285, func, target_55)
and func_56(vs_284, vq_len_285, func, target_56)
and func_58(vs_284, target_56, target_59, func, target_58)
and func_59(vq_1_284, vs_284, func, target_59)
and func_60(vs_284, vq_len_285, func, target_60)
and func_61(vs_284, vg_len_285, func, target_61)
and func_63(vs_284, target_61, target_64, func, target_63)
and func_64(vg_1_284, vs_284, func, target_64)
and func_65(vs_284, vg_len_285, func, target_65)
and func_66(vs_284, vy_len_285, func, target_66)
and func_67(vs_284, target_66, target_68, func, target_67)
and func_68(vy_1_284, vs_284, func, target_68)
and func_69(vret_286, func, target_69)
and func_70(vret_286, target_75, target_70)
and func_71(vlen_285, target_71)
and func_72(target_72)
and func_73(vhostkey_data_len_280, target_73)
and func_75(target_75)
and vhostkey_data_279.getType().hasName("const unsigned char *")
and vhostkey_data_len_280.getType().hasName("size_t")
and vdsactx_283.getType().hasName("DSA *")
and vp_1_284.getType().hasName("const unsigned char *")
and vq_1_284.getType().hasName("const unsigned char *")
and vg_1_284.getType().hasName("const unsigned char *")
and vy_1_284.getType().hasName("const unsigned char *")
and vs_284.getType().hasName("const unsigned char *")
and vp_len_285.getType().hasName("unsigned long")
and vq_len_285.getType().hasName("unsigned long")
and vg_len_285.getType().hasName("unsigned long")
and vy_len_285.getType().hasName("unsigned long")
and vlen_285.getType().hasName("unsigned long")
and vret_286.getType().hasName("int")
and vhostkey_data_279.getParentScope+() = func
and vhostkey_data_len_280.getParentScope+() = func
and vdsactx_283.getParentScope+() = func
and vp_1_284.getParentScope+() = func
and vq_1_284.getParentScope+() = func
and vg_1_284.getParentScope+() = func
and vy_1_284.getParentScope+() = func
and vs_284.getParentScope+() = func
and vp_len_285.getParentScope+() = func
and vq_len_285.getParentScope+() = func
and vg_len_285.getParentScope+() = func
and vy_len_285.getParentScope+() = func
and vlen_285.getParentScope+() = func
and vret_286.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
