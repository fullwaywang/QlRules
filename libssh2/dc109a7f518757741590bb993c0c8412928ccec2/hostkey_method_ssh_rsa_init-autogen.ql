/**
 * @name libssh2-dc109a7f518757741590bb993c0c8412928ccec2-hostkey_method_ssh_rsa_init
 * @id cpp/libssh2/dc109a7f518757741590bb993c0c8412928ccec2/hostkey-method-ssh-rsa-init
 * @description libssh2-dc109a7f518757741590bb993c0c8412928ccec2-src/hostkey.c-hostkey_method_ssh_rsa_init CVE-2019-3859
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

predicate func_1(Variable vlen_68, Literal target_1) {
		target_1.getValue()="7"
		and not target_1.getValue()="0"
		and target_1.getParent().(NEExpr).getParent().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vlen_68
}

predicate func_2(Variable vs_67, FunctionCall target_2) {
		target_2.getTarget().hasName("strncmp")
		and not target_2.getTarget().hasName("_libssh2_match_string")
		and target_2.getArgument(0).(VariableAccess).getTarget()=vs_67
		and target_2.getArgument(1).(StringLiteral).getValue()="ssh-rsa"
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

predicate func_11(Parameter vhostkey_data_len_63, BlockStmt target_48) {
	exists(RelationalOperation target_11 |
		 (target_11 instanceof GTExpr or target_11 instanceof LTExpr)
		and target_11.getLesserOperand().(VariableAccess).getTarget()=vhostkey_data_len_63
		and target_11.getGreaterOperand().(Literal).getValue()="19"
		and target_11.getParent().(IfStmt).getThen()=target_48)
}

predicate func_12(VariableAccess target_46, Function func) {
	exists(DoStmt target_12 |
		target_12.getCondition().(Literal).getValue()="0"
		and target_12.getStmt().(BlockStmt).toString() = "{ ... }"
		and target_12.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0)=target_12
		and target_12.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_46
		and target_12.getEnclosingFunction() = func)
}

predicate func_13(Parameter vhostkey_data_62) {
	exists(AssignExpr target_13 |
		target_13.getLValue().(ValueFieldAccess).getTarget().getName()="data"
		and target_13.getLValue().(ValueFieldAccess).getQualifier().(VariableAccess).getType().hasName("string_buf")
		and target_13.getRValue().(VariableAccess).getTarget()=vhostkey_data_62)
}

predicate func_14(Function func) {
	exists(AssignExpr target_14 |
		target_14.getLValue().(ValueFieldAccess).getTarget().getName()="dataptr"
		and target_14.getLValue().(ValueFieldAccess).getQualifier().(VariableAccess).getType().hasName("string_buf")
		and target_14.getRValue().(ValueFieldAccess).getTarget().getName()="data"
		and target_14.getRValue().(ValueFieldAccess).getQualifier().(VariableAccess).getType().hasName("string_buf")
		and target_14.getEnclosingFunction() = func)
}

predicate func_15(Parameter vhostkey_data_len_63, ExprStmt target_49) {
	exists(AssignExpr target_15 |
		target_15.getLValue().(ValueFieldAccess).getTarget().getName()="len"
		and target_15.getLValue().(ValueFieldAccess).getQualifier().(VariableAccess).getType().hasName("string_buf")
		and target_15.getRValue().(VariableAccess).getTarget()=vhostkey_data_len_63
		and target_49.getExpr().(VariableAccess).getLocation().isBefore(target_15.getRValue().(VariableAccess).getLocation()))
}

predicate func_16(Function func) {
	exists(AddressOfExpr target_16 |
		target_16.getOperand().(VariableAccess).getType().hasName("string_buf")
		and target_16.getParent().(FunctionCall).getParent().(NEExpr).getAnOperand() instanceof FunctionCall
		and target_16.getEnclosingFunction() = func)
}

predicate func_17(VariableAccess target_46, Function func) {
	exists(ReturnStmt target_17 |
		target_17.getExpr().(UnaryMinusExpr).getValue()="-1"
		and target_17.getParent().(IfStmt).getCondition()=target_46
		and target_17.getEnclosingFunction() = func)
}

predicate func_18(Variable ve_1_67, Variable ve_len_1_68, Function func) {
	exists(IfStmt target_18 |
		target_18.getCondition().(RelationalOperation).getLesserOperand().(AssignExpr).getLValue().(VariableAccess).getTarget()=ve_len_1_68
		and target_18.getCondition().(RelationalOperation).getLesserOperand().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("_libssh2_get_c_string")
		and target_18.getCondition().(RelationalOperation).getLesserOperand().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getType().hasName("string_buf")
		and target_18.getCondition().(RelationalOperation).getLesserOperand().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=ve_1_67
		and target_18.getCondition().(RelationalOperation).getGreaterOperand().(Literal).getValue()="0"
		and target_18.getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-1"
		and (func.getEntryPoint().(BlockStmt).getStmt(10)=target_18 or func.getEntryPoint().(BlockStmt).getStmt(10).getFollowingStmt()=target_18))
}

predicate func_19(Variable vn_1_67, Variable vn_len_1_68, Function func) {
	exists(IfStmt target_19 |
		target_19.getCondition().(RelationalOperation).getLesserOperand().(AssignExpr).getLValue().(VariableAccess).getTarget()=vn_len_1_68
		and target_19.getCondition().(RelationalOperation).getLesserOperand().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("_libssh2_get_c_string")
		and target_19.getCondition().(RelationalOperation).getLesserOperand().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getType().hasName("string_buf")
		and target_19.getCondition().(RelationalOperation).getLesserOperand().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vn_1_67
		and target_19.getCondition().(RelationalOperation).getGreaterOperand().(Literal).getValue()="0"
		and target_19.getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-1"
		and (func.getEntryPoint().(BlockStmt).getStmt(11)=target_19 or func.getEntryPoint().(BlockStmt).getStmt(11).getFollowingStmt()=target_19))
}

predicate func_20(Function func) {
	exists(IfStmt target_20 |
		target_20.getCondition() instanceof FunctionCall
		and target_20.getThen().(BlockStmt).getStmt(0).(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-1"
		and (func.getEntryPoint().(BlockStmt).getStmt(12)=target_20 or func.getEntryPoint().(BlockStmt).getStmt(12).getFollowingStmt()=target_20))
}

predicate func_21(Variable vrsactx_66, Variable ve_1_67, Variable vn_1_67, Variable ve_len_1_68, Variable vn_len_1_68, FunctionCall target_21) {
		target_21.getTarget().hasName("_libssh2_rsa_new")
		and target_21.getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vrsactx_66
		and target_21.getArgument(1).(VariableAccess).getTarget()=ve_1_67
		and target_21.getArgument(2).(VariableAccess).getTarget()=ve_len_1_68
		and target_21.getArgument(3).(VariableAccess).getTarget()=vn_1_67
		and target_21.getArgument(4).(VariableAccess).getTarget()=vn_len_1_68
		and target_21.getArgument(5).(Literal).getValue()="0"
		and target_21.getArgument(6).(Literal).getValue()="0"
		and target_21.getArgument(7).(Literal).getValue()="0"
		and target_21.getArgument(8).(Literal).getValue()="0"
		and target_21.getArgument(9).(Literal).getValue()="0"
		and target_21.getArgument(10).(Literal).getValue()="0"
		and target_21.getArgument(11).(Literal).getValue()="0"
		and target_21.getArgument(12).(Literal).getValue()="0"
		and target_21.getArgument(13).(Literal).getValue()="0"
		and target_21.getArgument(14).(Literal).getValue()="0"
		and target_21.getArgument(15).(Literal).getValue()="0"
		and target_21.getArgument(16).(Literal).getValue()="0"
}

predicate func_22(Parameter vhostkey_data_62, Variable vs_67, VariableAccess target_22) {
		target_22.getTarget()=vhostkey_data_62
		and target_22.getParent().(AssignExpr).getRValue() = target_22
		and target_22.getParent().(AssignExpr).getLValue().(VariableAccess).getTarget()=vs_67
}

predicate func_24(Parameter vhostkey_data_len_63, VariableAccess target_24) {
		target_24.getTarget()=vhostkey_data_len_63
}

predicate func_32(Parameter vhostkey_data_62, Variable vs_67, AssignExpr target_32) {
		target_32.getLValue().(VariableAccess).getTarget()=vs_67
		and target_32.getRValue().(VariableAccess).getTarget()=vhostkey_data_62
}

predicate func_33(Variable vs_67, Variable vlen_68, AssignExpr target_33) {
		target_33.getLValue().(VariableAccess).getTarget()=vlen_68
		and target_33.getRValue().(FunctionCall).getTarget().hasName("_libssh2_ntohu32")
		and target_33.getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs_67
}

predicate func_34(Variable vs_67, LogicalOrExpr target_35, Function func, ExprStmt target_34) {
		target_34.getExpr().(AssignPointerAddExpr).getLValue().(VariableAccess).getTarget()=vs_67
		and target_34.getExpr().(AssignPointerAddExpr).getRValue() instanceof Literal
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_34
}

predicate func_35(Variable vlen_68, BlockStmt target_48, LogicalOrExpr target_35) {
		target_35.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vlen_68
		and target_35.getAnOperand().(EqualityOperation).getAnOperand() instanceof Literal
		and target_35.getAnOperand().(EqualityOperation).getAnOperand() instanceof FunctionCall
		and target_35.getAnOperand().(EqualityOperation).getAnOperand() instanceof Literal
		and target_35.getParent().(IfStmt).getThen()=target_48
}

/*predicate func_36(Variable vlen_68, VariableAccess target_36) {
		target_36.getTarget()=vlen_68
}

*/
predicate func_37(Variable vs_67, Function func, ExprStmt target_37) {
		target_37.getExpr().(AssignPointerAddExpr).getLValue().(VariableAccess).getTarget()=vs_67
		and target_37.getExpr().(AssignPointerAddExpr).getRValue() instanceof Literal
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_37
}

predicate func_38(Variable vs_67, Variable ve_len_1_68, Function func, ExprStmt target_38) {
		target_38.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=ve_len_1_68
		and target_38.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("_libssh2_ntohu32")
		and target_38.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs_67
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_38
}

predicate func_39(Variable vs_67, ExprStmt target_38, ExprStmt target_40, Function func, ExprStmt target_39) {
		target_39.getExpr().(AssignPointerAddExpr).getLValue().(VariableAccess).getTarget()=vs_67
		and target_39.getExpr().(AssignPointerAddExpr).getRValue() instanceof Literal
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_39
		and target_38.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_39.getExpr().(AssignPointerAddExpr).getLValue().(VariableAccess).getLocation())
		and target_39.getExpr().(AssignPointerAddExpr).getLValue().(VariableAccess).getLocation().isBefore(target_40.getExpr().(AssignExpr).getRValue().(VariableAccess).getLocation())
}

predicate func_40(Variable vs_67, Variable ve_1_67, Function func, ExprStmt target_40) {
		target_40.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=ve_1_67
		and target_40.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vs_67
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_40
}

predicate func_41(Variable vs_67, Variable ve_len_1_68, Function func, ExprStmt target_41) {
		target_41.getExpr().(AssignPointerAddExpr).getLValue().(VariableAccess).getTarget()=vs_67
		and target_41.getExpr().(AssignPointerAddExpr).getRValue().(VariableAccess).getTarget()=ve_len_1_68
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_41
}

predicate func_42(Variable vs_67, Variable vn_len_1_68, Function func, ExprStmt target_42) {
		target_42.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vn_len_1_68
		and target_42.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("_libssh2_ntohu32")
		and target_42.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs_67
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_42
}

predicate func_43(Variable vs_67, ExprStmt target_42, ExprStmt target_44, Function func, ExprStmt target_43) {
		target_43.getExpr().(AssignPointerAddExpr).getLValue().(VariableAccess).getTarget()=vs_67
		and target_43.getExpr().(AssignPointerAddExpr).getRValue() instanceof Literal
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_43
		and target_42.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_43.getExpr().(AssignPointerAddExpr).getLValue().(VariableAccess).getLocation())
		and target_43.getExpr().(AssignPointerAddExpr).getLValue().(VariableAccess).getLocation().isBefore(target_44.getExpr().(AssignExpr).getRValue().(VariableAccess).getLocation())
}

predicate func_44(Variable vs_67, Variable vn_1_67, Function func, ExprStmt target_44) {
		target_44.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vn_1_67
		and target_44.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vs_67
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_44
}

predicate func_45(Variable vret_69, Function func, ExprStmt target_45) {
		target_45.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vret_69
		and target_45.getExpr().(AssignExpr).getRValue() instanceof FunctionCall
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_45
}

predicate func_46(Variable vret_69, BlockStmt target_51, VariableAccess target_46) {
		target_46.getTarget()=vret_69
		and target_46.getParent().(IfStmt).getThen()=target_51
}

predicate func_48(BlockStmt target_48) {
		target_48.getStmt(0).(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-1"
}

predicate func_49(Parameter vhostkey_data_len_63, ExprStmt target_49) {
		target_49.getExpr().(VariableAccess).getTarget()=vhostkey_data_len_63
}

predicate func_51(BlockStmt target_51) {
		target_51.getStmt(0).(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-1"
}

from Function func, Parameter vhostkey_data_62, Parameter vhostkey_data_len_63, Variable vrsactx_66, Variable vs_67, Variable ve_1_67, Variable vn_1_67, Variable vlen_68, Variable ve_len_1_68, Variable vn_len_1_68, Variable vret_69, Literal target_0, Literal target_1, FunctionCall target_2, Literal target_3, Literal target_4, Literal target_5, FunctionCall target_21, VariableAccess target_22, VariableAccess target_24, AssignExpr target_32, AssignExpr target_33, ExprStmt target_34, LogicalOrExpr target_35, ExprStmt target_37, ExprStmt target_38, ExprStmt target_39, ExprStmt target_40, ExprStmt target_41, ExprStmt target_42, ExprStmt target_43, ExprStmt target_44, ExprStmt target_45, VariableAccess target_46, BlockStmt target_48, ExprStmt target_49, BlockStmt target_51
where
func_0(func, target_0)
and func_1(vlen_68, target_1)
and func_2(vs_67, target_2)
and func_3(func, target_3)
and func_4(func, target_4)
and func_5(func, target_5)
and not func_11(vhostkey_data_len_63, target_48)
and not func_12(target_46, func)
and not func_13(vhostkey_data_62)
and not func_14(func)
and not func_15(vhostkey_data_len_63, target_49)
and not func_16(func)
and not func_17(target_46, func)
and not func_18(ve_1_67, ve_len_1_68, func)
and not func_19(vn_1_67, vn_len_1_68, func)
and not func_20(func)
and func_21(vrsactx_66, ve_1_67, vn_1_67, ve_len_1_68, vn_len_1_68, target_21)
and func_22(vhostkey_data_62, vs_67, target_22)
and func_24(vhostkey_data_len_63, target_24)
and func_32(vhostkey_data_62, vs_67, target_32)
and func_33(vs_67, vlen_68, target_33)
and func_34(vs_67, target_35, func, target_34)
and func_35(vlen_68, target_48, target_35)
and func_37(vs_67, func, target_37)
and func_38(vs_67, ve_len_1_68, func, target_38)
and func_39(vs_67, target_38, target_40, func, target_39)
and func_40(vs_67, ve_1_67, func, target_40)
and func_41(vs_67, ve_len_1_68, func, target_41)
and func_42(vs_67, vn_len_1_68, func, target_42)
and func_43(vs_67, target_42, target_44, func, target_43)
and func_44(vs_67, vn_1_67, func, target_44)
and func_45(vret_69, func, target_45)
and func_46(vret_69, target_51, target_46)
and func_48(target_48)
and func_49(vhostkey_data_len_63, target_49)
and func_51(target_51)
and vhostkey_data_62.getType().hasName("const unsigned char *")
and vhostkey_data_len_63.getType().hasName("size_t")
and vrsactx_66.getType().hasName("RSA *")
and vs_67.getType().hasName("const unsigned char *")
and ve_1_67.getType().hasName("const unsigned char *")
and vn_1_67.getType().hasName("const unsigned char *")
and vlen_68.getType().hasName("unsigned long")
and ve_len_1_68.getType().hasName("unsigned long")
and vn_len_1_68.getType().hasName("unsigned long")
and vret_69.getType().hasName("int")
and vhostkey_data_62.getParentScope+() = func
and vhostkey_data_len_63.getParentScope+() = func
and vrsactx_66.getParentScope+() = func
and vs_67.getParentScope+() = func
and ve_1_67.getParentScope+() = func
and vn_1_67.getParentScope+() = func
and vlen_68.getParentScope+() = func
and ve_len_1_68.getParentScope+() = func
and vn_len_1_68.getParentScope+() = func
and vret_69.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
