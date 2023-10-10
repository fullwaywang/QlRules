/**
 * @name libssh2-dc109a7f518757741590bb993c0c8412928ccec2-hostkey_method_ssh_ecdsa_init
 * @id cpp/libssh2/dc109a7f518757741590bb993c0c8412928ccec2/hostkey-method-ssh-ecdsa-init
 * @description libssh2-dc109a7f518757741590bb993c0c8412928ccec2-src/hostkey.c-hostkey_method_ssh_ecdsa_init CVE-2019-3859
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func, Literal target_0) {
		target_0.getValue()="23"
		and not target_0.getValue()="39"
		and target_0.getEnclosingFunction() = func
}

predicate func_1(Function func, Literal target_1) {
		target_1.getValue()="4"
		and not target_1.getValue()="0"
		and target_1.getParent().(AssignPointerAddExpr).getParent().(ExprStmt).getExpr() instanceof AssignPointerAddExpr
		and target_1.getEnclosingFunction() = func
}

predicate func_2(Variable vlen_509, ReturnStmt target_54, ExprStmt target_55, VariableAccess target_2) {
		target_2.getTarget()=vlen_509
		and target_2.getParent().(NEExpr).getAnOperand().(Literal).getValue()="19"
		and target_2.getParent().(NEExpr).getParent().(IfStmt).getThen()=target_54
		and target_55.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_2.getLocation())
}

predicate func_3(Function func, Literal target_3) {
		target_3.getValue()="19"
		and not target_3.getValue()="0"
		and target_3.getParent().(AssignPointerAddExpr).getParent().(ExprStmt).getExpr() instanceof AssignPointerAddExpr
		and target_3.getEnclosingFunction() = func
}

predicate func_4(Function func, Literal target_4) {
		target_4.getValue()="4"
		and not target_4.getValue()="0"
		and target_4.getParent().(AssignPointerAddExpr).getParent().(ExprStmt).getExpr() instanceof AssignPointerAddExpr
		and target_4.getEnclosingFunction() = func
}

predicate func_5(Function func, Literal target_5) {
		target_5.getValue()="8"
		and not target_5.getValue()="1"
		and target_5.getParent().(AssignPointerAddExpr).getParent().(ExprStmt).getExpr() instanceof AssignPointerAddExpr
		and target_5.getEnclosingFunction() = func
}

predicate func_6(Function func, Literal target_6) {
		target_6.getValue()="4"
		and not target_6.getValue()="0"
		and target_6.getParent().(AssignPointerAddExpr).getParent().(ExprStmt).getExpr() instanceof AssignPointerAddExpr
		and target_6.getEnclosingFunction() = func
}

predicate func_11(RelationalOperation target_56, Function func) {
	exists(DoStmt target_11 |
		target_11.getCondition().(Literal).getValue()="0"
		and target_11.getStmt().(BlockStmt).toString() = "{ ... }"
		and target_11.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0)=target_11
		and target_11.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_56
		and target_11.getEnclosingFunction() = func)
}

predicate func_12(RelationalOperation target_56, Function func) {
	exists(ReturnStmt target_12 |
		target_12.getExpr().(UnaryMinusExpr).getValue()="-1"
		and target_12.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1)=target_12
		and target_12.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_56
		and target_12.getEnclosingFunction() = func)
}

predicate func_13(Parameter vhostkey_data_503) {
	exists(AssignExpr target_13 |
		target_13.getLValue().(ValueFieldAccess).getTarget().getName()="data"
		and target_13.getLValue().(ValueFieldAccess).getQualifier().(VariableAccess).getType().hasName("string_buf")
		and target_13.getRValue().(VariableAccess).getTarget()=vhostkey_data_503)
}

predicate func_14(Function func) {
	exists(AssignExpr target_14 |
		target_14.getLValue().(ValueFieldAccess).getTarget().getName()="dataptr"
		and target_14.getLValue().(ValueFieldAccess).getQualifier().(VariableAccess).getType().hasName("string_buf")
		and target_14.getRValue().(ValueFieldAccess).getTarget().getName()="data"
		and target_14.getRValue().(ValueFieldAccess).getQualifier().(VariableAccess).getType().hasName("string_buf")
		and target_14.getEnclosingFunction() = func)
}

predicate func_15(Function func) {
	exists(ValueFieldAccess target_15 |
		target_15.getTarget().getName()="len"
		and target_15.getQualifier().(VariableAccess).getType().hasName("string_buf")
		and target_15.getEnclosingFunction() = func)
}

predicate func_16(Function func) {
	exists(FunctionCall target_16 |
		target_16.getTarget().hasName("_libssh2_get_c_string")
		and target_16.getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getType().hasName("string_buf")
		and target_16.getArgument(1).(AddressOfExpr).getOperand().(VariableAccess).getType().hasName("unsigned char *")
		and target_16.getEnclosingFunction() = func)
}

predicate func_20(Function func) {
	exists(FunctionCall target_20 |
		target_20.getTarget().hasName("_libssh2_get_c_string")
		and target_20.getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getType().hasName("string_buf")
		and target_20.getArgument(1).(AddressOfExpr).getOperand().(VariableAccess).getType().hasName("unsigned char *")
		and target_20.getEnclosingFunction() = func)
}

predicate func_24(Variable vkey_len_1_509, ReturnStmt target_57, ExprStmt target_49) {
	exists(RelationalOperation target_24 |
		 (target_24 instanceof GEExpr or target_24 instanceof LEExpr)
		and target_24.getLesserOperand().(AssignExpr).getLValue().(VariableAccess).getTarget()=vkey_len_1_509
		and target_24.getLesserOperand().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("_libssh2_get_c_string")
		and target_24.getLesserOperand().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getType().hasName("string_buf")
		and target_24.getLesserOperand().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(VariableAccess).getType().hasName("unsigned char *")
		and target_24.getGreaterOperand().(Literal).getValue()="0"
		and target_24.getParent().(IfStmt).getThen()=target_57
		and target_49.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_24.getLesserOperand().(AssignExpr).getLValue().(VariableAccess).getLocation()))
}

predicate func_25(Variable vecdsactx_507, Variable vkey_len_1_509, Variable vtype_510, ExprStmt target_58, FunctionCall target_59, LogicalAndExpr target_60, Function func) {
	exists(IfStmt target_25 |
		target_25.getCondition().(FunctionCall).getTarget().hasName("_libssh2_ecdsa_curve_name_with_octal_new")
		and target_25.getCondition().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vecdsactx_507
		and target_25.getCondition().(FunctionCall).getArgument(1).(VariableAccess).getType().hasName("unsigned char *")
		and target_25.getCondition().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vkey_len_1_509
		and target_25.getCondition().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vtype_510
		and target_25.getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-1"
		and (func.getEntryPoint().(BlockStmt).getStmt(15)=target_25 or func.getEntryPoint().(BlockStmt).getStmt(15).getFollowingStmt()=target_25)
		and target_25.getCondition().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getLocation().isBefore(target_58.getExpr().(AssignExpr).getRValue().(VariableAccess).getLocation())
		and target_25.getCondition().(FunctionCall).getArgument(2).(VariableAccess).getLocation().isBefore(target_59.getArgument(2).(VariableAccess).getLocation())
		and target_60.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getLocation().isBefore(target_25.getCondition().(FunctionCall).getArgument(3).(VariableAccess).getLocation()))
}

predicate func_28(Parameter vhostkey_data_503, Variable vs_508, VariableAccess target_28) {
		target_28.getTarget()=vhostkey_data_503
		and target_28.getParent().(AssignExpr).getRValue() = target_28
		and target_28.getParent().(AssignExpr).getLValue().(VariableAccess).getTarget()=vs_508
}

predicate func_34(Parameter vhostkey_data_503, Variable vs_508, AssignExpr target_34) {
		target_34.getLValue().(VariableAccess).getTarget()=vs_508
		and target_34.getRValue().(VariableAccess).getTarget()=vhostkey_data_503
}

predicate func_35(Variable vs_508, Variable vlen_509, VariableAccess target_35) {
		target_35.getTarget()=vlen_509
		and target_35.getParent().(AssignExpr).getLValue() = target_35
		and target_35.getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("_libssh2_ntohu32")
		and target_35.getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs_508
}

/*predicate func_36(Variable vs_508, FunctionCall target_36) {
		target_36.getTarget().hasName("_libssh2_ntohu32")
		and target_36.getArgument(0).(VariableAccess).getTarget()=vs_508
}

*/
predicate func_37(Variable vs_508, ExprStmt target_55, EqualityOperation target_63, AssignPointerAddExpr target_37) {
		target_37.getLValue().(VariableAccess).getTarget()=vs_508
		and target_37.getRValue() instanceof Literal
		and target_37.getLValue().(VariableAccess).getLocation().isBefore(target_63.getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
}

predicate func_38(Variable vs_508, EqualityOperation target_65, VariableAccess target_38) {
		target_38.getTarget()=vs_508
		and target_38.getParent().(FunctionCall).getParent().(EQExpr).getAnOperand().(FunctionCall).getTarget().hasName("strncmp")
		and target_38.getParent().(FunctionCall).getParent().(EQExpr).getAnOperand().(FunctionCall).getArgument(1).(StringLiteral).getValue()="ecdsa-sha2-nistp256"
		and target_38.getParent().(FunctionCall).getParent().(EQExpr).getAnOperand().(FunctionCall).getArgument(2).(Literal).getValue()="19"
		and target_38.getLocation().isBefore(target_65.getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
}

predicate func_39(Variable vs_508, EqualityOperation target_63, EqualityOperation target_66, VariableAccess target_39) {
		target_39.getTarget()=vs_508
		and target_39.getParent().(FunctionCall).getParent().(EQExpr).getAnOperand().(FunctionCall).getTarget().hasName("strncmp")
		and target_39.getParent().(FunctionCall).getParent().(EQExpr).getAnOperand().(FunctionCall).getArgument(1).(StringLiteral).getValue()="ecdsa-sha2-nistp384"
		and target_39.getParent().(FunctionCall).getParent().(EQExpr).getAnOperand().(FunctionCall).getArgument(2).(Literal).getValue()="19"
		and target_63.getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_39.getLocation())
		and target_39.getLocation().isBefore(target_66.getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
}

predicate func_40(Variable vs_508, EqualityOperation target_65, ExprStmt target_41, VariableAccess target_40) {
		target_40.getTarget()=vs_508
		and target_40.getParent().(FunctionCall).getParent().(EQExpr).getAnOperand().(FunctionCall).getTarget().hasName("strncmp")
		and target_40.getParent().(FunctionCall).getParent().(EQExpr).getAnOperand().(FunctionCall).getArgument(1).(StringLiteral).getValue()="ecdsa-sha2-nistp521"
		and target_40.getParent().(FunctionCall).getParent().(EQExpr).getAnOperand().(FunctionCall).getArgument(2).(Literal).getValue()="19"
		and target_65.getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_40.getLocation())
		and target_40.getLocation().isBefore(target_41.getExpr().(AssignPointerAddExpr).getLValue().(VariableAccess).getLocation())
}

predicate func_41(Variable vs_508, Function func, ExprStmt target_41) {
		target_41.getExpr().(AssignPointerAddExpr).getLValue().(VariableAccess).getTarget()=vs_508
		and target_41.getExpr().(AssignPointerAddExpr).getRValue() instanceof Literal
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_41
}

predicate func_42(Variable vs_508, Variable vn_len_509, Function func, ExprStmt target_42) {
		target_42.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vn_len_509
		and target_42.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("_libssh2_ntohu32")
		and target_42.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs_508
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_42
}

predicate func_43(Variable vs_508, ExprStmt target_42, LogicalAndExpr target_67, Function func, ExprStmt target_43) {
		target_43.getExpr().(AssignPointerAddExpr).getLValue().(VariableAccess).getTarget()=vs_508
		and target_43.getExpr().(AssignPointerAddExpr).getRValue() instanceof Literal
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_43
		and target_42.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_43.getExpr().(AssignPointerAddExpr).getLValue().(VariableAccess).getLocation())
		and target_43.getExpr().(AssignPointerAddExpr).getLValue().(VariableAccess).getLocation().isBefore(target_67.getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
}

predicate func_44(Variable vn_len_509, ReturnStmt target_68, VariableAccess target_44) {
		target_44.getTarget()=vn_len_509
		and target_44.getParent().(NEExpr).getAnOperand().(Literal).getValue()="8"
		and target_44.getParent().(NEExpr).getParent().(IfStmt).getThen()=target_68
}

predicate func_45(Variable vs_508, ExprStmt target_43, LogicalAndExpr target_69, VariableAccess target_45) {
		target_45.getTarget()=vs_508
		and target_45.getParent().(FunctionCall).getParent().(NEExpr).getAnOperand().(FunctionCall).getTarget().hasName("strncmp")
		and target_45.getParent().(FunctionCall).getParent().(NEExpr).getAnOperand().(FunctionCall).getArgument(1).(StringLiteral).getValue()="nistp256"
		and target_45.getParent().(FunctionCall).getParent().(NEExpr).getAnOperand().(FunctionCall).getArgument(2).(Literal).getValue()="8"
		and target_43.getExpr().(AssignPointerAddExpr).getLValue().(VariableAccess).getLocation().isBefore(target_45.getLocation())
		and target_45.getLocation().isBefore(target_69.getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
}

predicate func_46(Variable vs_508, LogicalAndExpr target_67, LogicalAndExpr target_60, VariableAccess target_46) {
		target_46.getTarget()=vs_508
		and target_46.getParent().(FunctionCall).getParent().(NEExpr).getAnOperand().(FunctionCall).getTarget().hasName("strncmp")
		and target_46.getParent().(FunctionCall).getParent().(NEExpr).getAnOperand().(FunctionCall).getArgument(1).(StringLiteral).getValue()="nistp384"
		and target_46.getParent().(FunctionCall).getParent().(NEExpr).getAnOperand().(FunctionCall).getArgument(2).(Literal).getValue()="8"
		and target_67.getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_46.getLocation())
		and target_46.getLocation().isBefore(target_60.getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
}

predicate func_47(Variable vs_508, LogicalAndExpr target_69, ExprStmt target_48, VariableAccess target_47) {
		target_47.getTarget()=vs_508
		and target_47.getParent().(FunctionCall).getParent().(NEExpr).getAnOperand().(FunctionCall).getTarget().hasName("strncmp")
		and target_47.getParent().(FunctionCall).getParent().(NEExpr).getAnOperand().(FunctionCall).getArgument(1).(StringLiteral).getValue()="nistp521"
		and target_47.getParent().(FunctionCall).getParent().(NEExpr).getAnOperand().(FunctionCall).getArgument(2).(Literal).getValue()="8"
		and target_69.getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_47.getLocation())
		and target_47.getLocation().isBefore(target_48.getExpr().(AssignPointerAddExpr).getLValue().(VariableAccess).getLocation())
}

predicate func_48(Variable vs_508, Function func, ExprStmt target_48) {
		target_48.getExpr().(AssignPointerAddExpr).getLValue().(VariableAccess).getTarget()=vs_508
		and target_48.getExpr().(AssignPointerAddExpr).getRValue() instanceof Literal
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_48
}

predicate func_49(Variable vs_508, Variable vkey_len_1_509, Function func, ExprStmt target_49) {
		target_49.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vkey_len_1_509
		and target_49.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("_libssh2_ntohu32")
		and target_49.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs_508
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_49
}

predicate func_50(Variable vs_508, ExprStmt target_49, ExprStmt target_51, Function func, ExprStmt target_50) {
		target_50.getExpr().(AssignPointerAddExpr).getLValue().(VariableAccess).getTarget()=vs_508
		and target_50.getExpr().(AssignPointerAddExpr).getRValue() instanceof Literal
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_50
		and target_49.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_50.getExpr().(AssignPointerAddExpr).getLValue().(VariableAccess).getLocation())
		and target_50.getExpr().(AssignPointerAddExpr).getLValue().(VariableAccess).getLocation().isBefore(target_51.getExpr().(AssignExpr).getRValue().(VariableAccess).getLocation())
}

predicate func_51(Variable vs_508, Variable vk_508, Function func, ExprStmt target_51) {
		target_51.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vk_508
		and target_51.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vs_508
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_51
}

/*predicate func_52(Variable vecdsactx_507, Variable vk_508, Variable vkey_len_1_509, Variable vtype_510, ReturnStmt target_57, VariableAccess target_52) {
		target_52.getTarget()=vk_508
		and target_52.getParent().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vecdsactx_507
		and target_52.getParent().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vkey_len_1_509
		and target_52.getParent().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vtype_510
		and target_52.getParent().(FunctionCall).getParent().(IfStmt).getThen()=target_57
}

*/
/*predicate func_53(Variable vecdsactx_507, Variable vk_508, Variable vkey_len_1_509, Variable vtype_510, ReturnStmt target_57, VariableAccess target_53) {
		target_53.getTarget()=vkey_len_1_509
		and target_53.getParent().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vecdsactx_507
		and target_53.getParent().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vk_508
		and target_53.getParent().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vtype_510
		and target_53.getParent().(FunctionCall).getParent().(IfStmt).getThen()=target_57
}

*/
predicate func_54(ReturnStmt target_54) {
		target_54.getExpr().(UnaryMinusExpr).getValue()="-1"
}

predicate func_55(Variable vlen_509, ExprStmt target_55) {
		target_55.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vlen_509
		and target_55.getExpr().(AssignExpr).getRValue() instanceof FunctionCall
}

predicate func_56(RelationalOperation target_56) {
		 (target_56 instanceof GTExpr or target_56 instanceof LTExpr)
		and target_56.getGreaterOperand() instanceof Literal
}

predicate func_57(ReturnStmt target_57) {
		target_57.getExpr().(UnaryMinusExpr).getValue()="-1"
}

predicate func_58(Variable vecdsactx_507, ExprStmt target_58) {
		target_58.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vecdsactx_507
}

predicate func_59(Variable vecdsactx_507, Variable vk_508, Variable vkey_len_1_509, Variable vtype_510, FunctionCall target_59) {
		target_59.getTarget().hasName("_libssh2_ecdsa_curve_name_with_octal_new")
		and target_59.getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vecdsactx_507
		and target_59.getArgument(1).(VariableAccess).getTarget()=vk_508
		and target_59.getArgument(2).(VariableAccess).getTarget()=vkey_len_1_509
		and target_59.getArgument(3).(VariableAccess).getTarget()=vtype_510
}

predicate func_60(Variable vs_508, Variable vtype_510, LogicalAndExpr target_60) {
		target_60.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vtype_510
		and target_60.getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getTarget().hasName("strncmp")
		and target_60.getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs_508
		and target_60.getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(1).(StringLiteral).getValue()="nistp521"
		and target_60.getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(2).(Literal).getValue()="8"
		and target_60.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
}

predicate func_63(Variable vs_508, EqualityOperation target_63) {
		target_63.getAnOperand().(FunctionCall).getTarget().hasName("strncmp")
		and target_63.getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs_508
		and target_63.getAnOperand().(FunctionCall).getArgument(1).(StringLiteral).getValue()="ecdsa-sha2-nistp256"
		and target_63.getAnOperand().(FunctionCall).getArgument(2).(Literal).getValue()="19"
		and target_63.getAnOperand().(Literal).getValue()="0"
}

predicate func_65(Variable vs_508, EqualityOperation target_65) {
		target_65.getAnOperand().(FunctionCall).getTarget().hasName("strncmp")
		and target_65.getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs_508
		and target_65.getAnOperand().(FunctionCall).getArgument(1).(StringLiteral).getValue()="ecdsa-sha2-nistp384"
		and target_65.getAnOperand().(FunctionCall).getArgument(2).(Literal).getValue()="19"
		and target_65.getAnOperand().(Literal).getValue()="0"
}

predicate func_66(Variable vs_508, EqualityOperation target_66) {
		target_66.getAnOperand().(FunctionCall).getTarget().hasName("strncmp")
		and target_66.getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs_508
		and target_66.getAnOperand().(FunctionCall).getArgument(1).(StringLiteral).getValue()="ecdsa-sha2-nistp521"
		and target_66.getAnOperand().(FunctionCall).getArgument(2).(Literal).getValue()="19"
		and target_66.getAnOperand().(Literal).getValue()="0"
}

predicate func_67(Variable vs_508, Variable vtype_510, LogicalAndExpr target_67) {
		target_67.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vtype_510
		and target_67.getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getTarget().hasName("strncmp")
		and target_67.getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs_508
		and target_67.getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(1).(StringLiteral).getValue()="nistp256"
		and target_67.getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(2).(Literal).getValue()="8"
		and target_67.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
}

predicate func_68(ReturnStmt target_68) {
		target_68.getExpr().(UnaryMinusExpr).getValue()="-1"
}

predicate func_69(Variable vs_508, Variable vtype_510, LogicalAndExpr target_69) {
		target_69.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vtype_510
		and target_69.getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getTarget().hasName("strncmp")
		and target_69.getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs_508
		and target_69.getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(1).(StringLiteral).getValue()="nistp384"
		and target_69.getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(2).(Literal).getValue()="8"
		and target_69.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
}

from Function func, Parameter vhostkey_data_503, Variable vecdsactx_507, Variable vs_508, Variable vk_508, Variable vlen_509, Variable vkey_len_1_509, Variable vn_len_509, Variable vtype_510, Literal target_0, Literal target_1, VariableAccess target_2, Literal target_3, Literal target_4, Literal target_5, Literal target_6, VariableAccess target_28, AssignExpr target_34, VariableAccess target_35, AssignPointerAddExpr target_37, VariableAccess target_38, VariableAccess target_39, VariableAccess target_40, ExprStmt target_41, ExprStmt target_42, ExprStmt target_43, VariableAccess target_44, VariableAccess target_45, VariableAccess target_46, VariableAccess target_47, ExprStmt target_48, ExprStmt target_49, ExprStmt target_50, ExprStmt target_51, ReturnStmt target_54, ExprStmt target_55, RelationalOperation target_56, ReturnStmt target_57, ExprStmt target_58, FunctionCall target_59, LogicalAndExpr target_60, EqualityOperation target_63, EqualityOperation target_65, EqualityOperation target_66, LogicalAndExpr target_67, ReturnStmt target_68, LogicalAndExpr target_69
where
func_0(func, target_0)
and func_1(func, target_1)
and func_2(vlen_509, target_54, target_55, target_2)
and func_3(func, target_3)
and func_4(func, target_4)
and func_5(func, target_5)
and func_6(func, target_6)
and not func_11(target_56, func)
and not func_12(target_56, func)
and not func_13(vhostkey_data_503)
and not func_14(func)
and not func_15(func)
and not func_16(func)
and not func_20(func)
and not func_24(vkey_len_1_509, target_57, target_49)
and not func_25(vecdsactx_507, vkey_len_1_509, vtype_510, target_58, target_59, target_60, func)
and func_28(vhostkey_data_503, vs_508, target_28)
and func_34(vhostkey_data_503, vs_508, target_34)
and func_35(vs_508, vlen_509, target_35)
and func_37(vs_508, target_55, target_63, target_37)
and func_38(vs_508, target_65, target_38)
and func_39(vs_508, target_63, target_66, target_39)
and func_40(vs_508, target_65, target_41, target_40)
and func_41(vs_508, func, target_41)
and func_42(vs_508, vn_len_509, func, target_42)
and func_43(vs_508, target_42, target_67, func, target_43)
and func_44(vn_len_509, target_68, target_44)
and func_45(vs_508, target_43, target_69, target_45)
and func_46(vs_508, target_67, target_60, target_46)
and func_47(vs_508, target_69, target_48, target_47)
and func_48(vs_508, func, target_48)
and func_49(vs_508, vkey_len_1_509, func, target_49)
and func_50(vs_508, target_49, target_51, func, target_50)
and func_51(vs_508, vk_508, func, target_51)
and func_54(target_54)
and func_55(vlen_509, target_55)
and func_56(target_56)
and func_57(target_57)
and func_58(vecdsactx_507, target_58)
and func_59(vecdsactx_507, vk_508, vkey_len_1_509, vtype_510, target_59)
and func_60(vs_508, vtype_510, target_60)
and func_63(vs_508, target_63)
and func_65(vs_508, target_65)
and func_66(vs_508, target_66)
and func_67(vs_508, vtype_510, target_67)
and func_68(target_68)
and func_69(vs_508, vtype_510, target_69)
and vhostkey_data_503.getType().hasName("const unsigned char *")
and vecdsactx_507.getType().hasName("EC_KEY *")
and vs_508.getType().hasName("const unsigned char *")
and vk_508.getType().hasName("const unsigned char *")
and vlen_509.getType().hasName("size_t")
and vkey_len_1_509.getType().hasName("size_t")
and vn_len_509.getType().hasName("size_t")
and vtype_510.getType().hasName("libssh2_curve_type")
and vhostkey_data_503.getParentScope+() = func
and vecdsactx_507.getParentScope+() = func
and vs_508.getParentScope+() = func
and vk_508.getParentScope+() = func
and vlen_509.getParentScope+() = func
and vkey_len_1_509.getParentScope+() = func
and vn_len_509.getParentScope+() = func
and vtype_510.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
