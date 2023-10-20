/**
 * @name libssh2-dc109a7f518757741590bb993c0c8412928ccec2-kex_method_diffie_hellman_group_exchange_sha1_key_exchange
 * @id cpp/libssh2/dc109a7f518757741590bb993c0c8412928ccec2/kex-method-diffie-hellman-group-exchange-sha1-key-exchange
 * @description libssh2-dc109a7f518757741590bb993c0c8412928ccec2-src/kex.c-kex_method_diffie_hellman_group_exchange_sha1_key_exchange CVE-2019-3859
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_2(Parameter vkey_state_1584, Initializer target_2) {
		target_2.getExpr().(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="data"
		and target_2.getExpr().(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vkey_state_1584
		and target_2.getExpr().(PointerArithmeticOperation).getAnOperand().(Literal).getValue()="1"
}

/*predicate func_3(Parameter vkey_state_1584, EqualityOperation target_36, Literal target_3) {
		target_3.getValue()="1"
		and not target_3.getValue()="0"
		and target_3.getParent().(PointerAddExpr).getParent().(Initializer).getExpr().(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="data"
		and target_3.getParent().(PointerAddExpr).getParent().(Initializer).getExpr().(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vkey_state_1584
		and target_36.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_3.getParent().(PointerAddExpr).getParent().(Initializer).getExpr().(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
}

*/
predicate func_4(Variable vs_1645, VariableAccess target_4) {
		target_4.getTarget()=vs_1645
		and target_4.getParent().(FunctionCall).getParent().(AssignExpr).getRValue() instanceof FunctionCall
}

predicate func_5(Variable vs_1645, VariableAccess target_5) {
		target_5.getTarget()=vs_1645
}

predicate func_6(Function func, Literal target_6) {
		target_6.getValue()="4"
		and not target_6.getValue()="0"
		and target_6.getParent().(AssignPointerAddExpr).getParent().(ExprStmt).getExpr() instanceof AssignPointerAddExpr
		and target_6.getEnclosingFunction() = func
}

predicate func_7(Parameter vkey_state_1584, Variable vp_len_1586, Variable vs_1645, VariableAccess target_7) {
		target_7.getTarget()=vs_1645
		and target_7.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("BN_bin2bn")
		and target_7.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vp_len_1586
		and target_7.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(PointerFieldAccess).getTarget().getName()="p"
		and target_7.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vkey_state_1584
}

predicate func_8(Variable vs_1645, VariableAccess target_8) {
		target_8.getTarget()=vs_1645
}

predicate func_9(Function func, Literal target_9) {
		target_9.getValue()="4"
		and not target_9.getValue()="9"
		and target_9.getParent().(AssignPointerAddExpr).getParent().(ExprStmt).getExpr() instanceof AssignPointerAddExpr
		and target_9.getEnclosingFunction() = func
}

predicate func_12(Parameter vsession_1584, Parameter vkey_state_1584, Variable vret_1587, EqualityOperation target_36, ExprStmt target_37, PointerArithmeticOperation target_38) {
	exists(IfStmt target_12 |
		target_12.getCondition().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getTarget().getName()="data_len"
		and target_12.getCondition().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vkey_state_1584
		and target_12.getCondition().(RelationalOperation).getGreaterOperand().(Literal).getValue()="9"
		and target_12.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vret_1587
		and target_12.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("_libssh2_error")
		and target_12.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsession_1584
		and target_12.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(UnaryMinusExpr).getValue()="-14"
		and target_12.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(StringLiteral).getValue()="Unexpected key length"
		and target_12.getThen().(BlockStmt).getStmt(1).(GotoStmt).toString() = "goto ..."
		and target_12.getThen().(BlockStmt).getStmt(1).(GotoStmt).getName() ="dh_gex_clean_exit"
		and target_12.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(3)=target_12
		and target_12.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_36
		and target_37.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_12.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_38.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_12.getCondition().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

/*predicate func_13(Parameter vsession_1584, Variable vret_1587, ExprStmt target_37) {
	exists(AssignExpr target_13 |
		target_13.getLValue().(VariableAccess).getTarget()=vret_1587
		and target_13.getRValue().(FunctionCall).getTarget().hasName("_libssh2_error")
		and target_13.getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsession_1584
		and target_13.getRValue().(FunctionCall).getArgument(1).(UnaryMinusExpr).getValue()="-14"
		and target_13.getRValue().(FunctionCall).getArgument(2).(StringLiteral).getValue()="Unexpected key length"
		and target_37.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_13.getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

*/
predicate func_14(Parameter vkey_state_1584, ExprStmt target_39) {
	exists(AssignExpr target_14 |
		target_14.getLValue().(ValueFieldAccess).getTarget().getName()="data"
		and target_14.getLValue().(ValueFieldAccess).getQualifier().(VariableAccess).getType().hasName("string_buf")
		and target_14.getRValue().(PointerFieldAccess).getTarget().getName()="data"
		and target_14.getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vkey_state_1584
		and target_14.getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_39.getExpr().(FunctionCall).getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_15(Function func) {
	exists(AssignExpr target_15 |
		target_15.getLValue().(ValueFieldAccess).getTarget().getName()="dataptr"
		and target_15.getLValue().(ValueFieldAccess).getQualifier().(VariableAccess).getType().hasName("string_buf")
		and target_15.getRValue().(ValueFieldAccess).getTarget().getName()="data"
		and target_15.getRValue().(ValueFieldAccess).getQualifier().(VariableAccess).getType().hasName("string_buf")
		and target_15.getEnclosingFunction() = func)
}

predicate func_16(Parameter vkey_state_1584, ExprStmt target_39, ExprStmt target_40) {
	exists(AssignExpr target_16 |
		target_16.getLValue().(ValueFieldAccess).getTarget().getName()="len"
		and target_16.getLValue().(ValueFieldAccess).getQualifier().(VariableAccess).getType().hasName("string_buf")
		and target_16.getRValue().(PointerFieldAccess).getTarget().getName()="data_len"
		and target_16.getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vkey_state_1584
		and target_39.getExpr().(FunctionCall).getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_16.getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_16.getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_40.getExpr().(FunctionCall).getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_17(Function func) {
	exists(PostfixIncrExpr target_17 |
		target_17.getOperand().(ValueFieldAccess).getTarget().getName()="dataptr"
		and target_17.getOperand().(ValueFieldAccess).getQualifier().(VariableAccess).getType().hasName("string_buf")
		and target_17.getEnclosingFunction() = func)
}

predicate func_18(Parameter vsession_1584, Variable vp_len_1586, Variable vret_1587, EqualityOperation target_36, ExprStmt target_42) {
	exists(IfStmt target_18 |
		target_18.getCondition().(RelationalOperation).getLesserOperand().(AssignExpr).getLValue().(VariableAccess).getTarget()=vp_len_1586
		and target_18.getCondition().(RelationalOperation).getLesserOperand().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("_libssh2_get_bignum_bytes")
		and target_18.getCondition().(RelationalOperation).getLesserOperand().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getType().hasName("string_buf")
		and target_18.getCondition().(RelationalOperation).getLesserOperand().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(VariableAccess).getType().hasName("unsigned char *")
		and target_18.getCondition().(RelationalOperation).getGreaterOperand().(Literal).getValue()="0"
		and target_18.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vret_1587
		and target_18.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("_libssh2_error")
		and target_18.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsession_1584
		and target_18.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(UnaryMinusExpr).getValue()="-14"
		and target_18.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(StringLiteral).getValue()="Unexpected value"
		and target_18.getThen().(BlockStmt).getStmt(1).(GotoStmt).toString() = "goto ..."
		and target_18.getThen().(BlockStmt).getStmt(1).(GotoStmt).getName() ="dh_gex_clean_exit"
		and target_18.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(8)=target_18
		and target_18.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_36
		and target_18.getCondition().(RelationalOperation).getLesserOperand().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_42.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(VariableAccess).getLocation()))
}

/*predicate func_19(Parameter vsession_1584, Variable vret_1587) {
	exists(AssignExpr target_19 |
		target_19.getLValue().(VariableAccess).getTarget()=vret_1587
		and target_19.getRValue().(FunctionCall).getTarget().hasName("_libssh2_error")
		and target_19.getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsession_1584
		and target_19.getRValue().(FunctionCall).getArgument(1).(UnaryMinusExpr).getValue()="-14"
		and target_19.getRValue().(FunctionCall).getArgument(2).(StringLiteral).getValue()="Unexpected value")
}

*/
predicate func_20(Parameter vsession_1584, Variable vg_len_1586, Variable vret_1587, EqualityOperation target_36, ExprStmt target_42) {
	exists(IfStmt target_20 |
		target_20.getCondition().(RelationalOperation).getLesserOperand().(AssignExpr).getLValue().(VariableAccess).getTarget()=vg_len_1586
		and target_20.getCondition().(RelationalOperation).getLesserOperand().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("_libssh2_get_bignum_bytes")
		and target_20.getCondition().(RelationalOperation).getLesserOperand().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getType().hasName("string_buf")
		and target_20.getCondition().(RelationalOperation).getLesserOperand().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(VariableAccess).getType().hasName("unsigned char *")
		and target_20.getCondition().(RelationalOperation).getGreaterOperand().(Literal).getValue()="0"
		and target_20.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vret_1587
		and target_20.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("_libssh2_error")
		and target_20.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsession_1584
		and target_20.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(UnaryMinusExpr).getValue()="-14"
		and target_20.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(StringLiteral).getValue()="Unexpected value"
		and target_20.getThen().(BlockStmt).getStmt(1).(GotoStmt).toString() = "goto ..."
		and target_20.getThen().(BlockStmt).getStmt(1).(GotoStmt).getName() ="dh_gex_clean_exit"
		and target_20.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(9)=target_20
		and target_20.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_36
		and target_20.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_42.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

/*predicate func_21(Parameter vsession_1584, Variable vret_1587, ExprStmt target_42) {
	exists(AssignExpr target_21 |
		target_21.getLValue().(VariableAccess).getTarget()=vret_1587
		and target_21.getRValue().(FunctionCall).getTarget().hasName("_libssh2_error")
		and target_21.getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsession_1584
		and target_21.getRValue().(FunctionCall).getArgument(1).(UnaryMinusExpr).getValue()="-14"
		and target_21.getRValue().(FunctionCall).getArgument(2).(StringLiteral).getValue()="Unexpected value"
		and target_21.getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_42.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

*/
predicate func_22(Parameter vkey_state_1584, Variable vp_len_1586, EqualityOperation target_36, ExprStmt target_39) {
	exists(ExprStmt target_22 |
		target_22.getExpr().(FunctionCall).getTarget().hasName("BN_bin2bn")
		and target_22.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getType().hasName("unsigned char *")
		and target_22.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vp_len_1586
		and target_22.getExpr().(FunctionCall).getArgument(2).(PointerFieldAccess).getTarget().getName()="p"
		and target_22.getExpr().(FunctionCall).getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vkey_state_1584
		and target_22.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(10)=target_22
		and target_22.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_36
		and target_22.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation().isBefore(target_39.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation()))
}

predicate func_24(Parameter vkey_state_1584, Variable vg_len_1586, EqualityOperation target_36, ExprStmt target_42, ExprStmt target_40) {
	exists(ExprStmt target_24 |
		target_24.getExpr().(FunctionCall).getTarget().hasName("BN_bin2bn")
		and target_24.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getType().hasName("unsigned char *")
		and target_24.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vg_len_1586
		and target_24.getExpr().(FunctionCall).getArgument(2).(PointerFieldAccess).getTarget().getName()="g"
		and target_24.getExpr().(FunctionCall).getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vkey_state_1584
		and target_24.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(11)=target_24
		and target_24.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_36
		and target_24.getExpr().(FunctionCall).getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_42.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_24.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation().isBefore(target_40.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation()))
}

predicate func_26(Parameter vkey_state_1584, PointerFieldAccess target_26) {
		target_26.getTarget().getName()="data"
		and target_26.getQualifier().(VariableAccess).getTarget()=vkey_state_1584
}

predicate func_27(Function func, DeclStmt target_27) {
		func.getEntryPoint().(BlockStmt).getAStmt()=target_27
}

predicate func_28(Variable vp_len_1586, Variable vs_1645, AssignExpr target_28) {
		target_28.getLValue().(VariableAccess).getTarget()=vp_len_1586
		and target_28.getRValue().(FunctionCall).getTarget().hasName("_libssh2_ntohu32")
		and target_28.getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs_1645
}

predicate func_29(Variable vs_1645, ExprStmt target_39, AssignPointerAddExpr target_29) {
		target_29.getLValue().(VariableAccess).getTarget()=vs_1645
		and target_29.getRValue() instanceof Literal
		and target_29.getLValue().(VariableAccess).getLocation().isBefore(target_39.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
}

predicate func_30(Parameter vkey_state_1584, Variable vp_len_1586, Variable vs_1645, VariableAccess target_30) {
		target_30.getTarget()=vp_len_1586
		and target_30.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("BN_bin2bn")
		and target_30.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs_1645
		and target_30.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(PointerFieldAccess).getTarget().getName()="p"
		and target_30.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vkey_state_1584
}

predicate func_31(Variable vp_len_1586, Variable vs_1645, AssignPointerAddExpr target_31) {
		target_31.getLValue().(VariableAccess).getTarget()=vs_1645
		and target_31.getRValue().(VariableAccess).getTarget()=vp_len_1586
}

predicate func_32(Variable vg_len_1586, Variable vs_1645, AssignExpr target_32) {
		target_32.getLValue().(VariableAccess).getTarget()=vg_len_1586
		and target_32.getRValue().(FunctionCall).getTarget().hasName("_libssh2_ntohu32")
		and target_32.getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs_1645
}

predicate func_33(Variable vs_1645, ExprStmt target_40, AssignPointerAddExpr target_33) {
		target_33.getLValue().(VariableAccess).getTarget()=vs_1645
		and target_33.getRValue() instanceof Literal
		and target_33.getLValue().(VariableAccess).getLocation().isBefore(target_40.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
}

/*predicate func_34(Parameter vkey_state_1584, Variable vg_len_1586, Variable vs_1645, ExprStmt target_42, VariableAccess target_34) {
		target_34.getTarget()=vs_1645
		and target_34.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("BN_bin2bn")
		and target_34.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vg_len_1586
		and target_34.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(PointerFieldAccess).getTarget().getName()="g"
		and target_34.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vkey_state_1584
		and target_34.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_42.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
}

*/
/*predicate func_35(Parameter vkey_state_1584, Variable vg_len_1586, Variable vs_1645, VariableAccess target_35) {
		target_35.getTarget()=vg_len_1586
		and target_35.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("BN_bin2bn")
		and target_35.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs_1645
		and target_35.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(PointerFieldAccess).getTarget().getName()="g"
		and target_35.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vkey_state_1584
}

*/
predicate func_36(Parameter vkey_state_1584, EqualityOperation target_36) {
		target_36.getAnOperand().(PointerFieldAccess).getTarget().getName()="state"
		and target_36.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vkey_state_1584
}

predicate func_37(Parameter vsession_1584, Variable vret_1587, ExprStmt target_37) {
		target_37.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vret_1587
		and target_37.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("_libssh2_error")
		and target_37.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsession_1584
		and target_37.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(StringLiteral).getValue()="Timeout waiting for GEX_GROUP reply"
}

predicate func_38(Parameter vkey_state_1584, PointerArithmeticOperation target_38) {
		target_38.getAnOperand().(PointerFieldAccess).getTarget().getName()="data"
		and target_38.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vkey_state_1584
		and target_38.getAnOperand() instanceof Literal
}

predicate func_39(Parameter vkey_state_1584, Variable vp_len_1586, Variable vs_1645, ExprStmt target_39) {
		target_39.getExpr().(FunctionCall).getTarget().hasName("BN_bin2bn")
		and target_39.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs_1645
		and target_39.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vp_len_1586
		and target_39.getExpr().(FunctionCall).getArgument(2).(PointerFieldAccess).getTarget().getName()="p"
		and target_39.getExpr().(FunctionCall).getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vkey_state_1584
}

predicate func_40(Parameter vkey_state_1584, Variable vg_len_1586, Variable vs_1645, ExprStmt target_40) {
		target_40.getExpr().(FunctionCall).getTarget().hasName("BN_bin2bn")
		and target_40.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs_1645
		and target_40.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vg_len_1586
		and target_40.getExpr().(FunctionCall).getArgument(2).(PointerFieldAccess).getTarget().getName()="g"
		and target_40.getExpr().(FunctionCall).getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vkey_state_1584
}

predicate func_42(Parameter vsession_1584, Parameter vkey_state_1584, Variable vp_len_1586, Variable vret_1587, ExprStmt target_42) {
		target_42.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vret_1587
		and target_42.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("diffie_hellman_sha1")
		and target_42.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsession_1584
		and target_42.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="g"
		and target_42.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vkey_state_1584
		and target_42.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(PointerFieldAccess).getTarget().getName()="p"
		and target_42.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vkey_state_1584
		and target_42.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vp_len_1586
		and target_42.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(4).(Literal).getValue()="32"
		and target_42.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(5).(Literal).getValue()="33"
		and target_42.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(6).(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="data"
		and target_42.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(6).(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vkey_state_1584
		and target_42.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(6).(PointerArithmeticOperation).getAnOperand().(Literal).getValue()="1"
		and target_42.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(7).(SubExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="data_len"
		and target_42.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(7).(SubExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vkey_state_1584
		and target_42.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(7).(SubExpr).getRightOperand().(Literal).getValue()="1"
		and target_42.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(8).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="exchange_state"
		and target_42.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(8).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vkey_state_1584
}

from Function func, Parameter vsession_1584, Parameter vkey_state_1584, Variable vp_len_1586, Variable vg_len_1586, Variable vret_1587, Variable vs_1645, Initializer target_2, VariableAccess target_4, VariableAccess target_5, Literal target_6, VariableAccess target_7, VariableAccess target_8, Literal target_9, PointerFieldAccess target_26, DeclStmt target_27, AssignExpr target_28, AssignPointerAddExpr target_29, VariableAccess target_30, AssignPointerAddExpr target_31, AssignExpr target_32, AssignPointerAddExpr target_33, EqualityOperation target_36, ExprStmt target_37, PointerArithmeticOperation target_38, ExprStmt target_39, ExprStmt target_40, ExprStmt target_42
where
func_2(vkey_state_1584, target_2)
and func_4(vs_1645, target_4)
and func_5(vs_1645, target_5)
and func_6(func, target_6)
and func_7(vkey_state_1584, vp_len_1586, vs_1645, target_7)
and func_8(vs_1645, target_8)
and func_9(func, target_9)
and not func_12(vsession_1584, vkey_state_1584, vret_1587, target_36, target_37, target_38)
and not func_14(vkey_state_1584, target_39)
and not func_15(func)
and not func_16(vkey_state_1584, target_39, target_40)
and not func_17(func)
and not func_18(vsession_1584, vp_len_1586, vret_1587, target_36, target_42)
and not func_20(vsession_1584, vg_len_1586, vret_1587, target_36, target_42)
and not func_22(vkey_state_1584, vp_len_1586, target_36, target_39)
and not func_24(vkey_state_1584, vg_len_1586, target_36, target_42, target_40)
and func_26(vkey_state_1584, target_26)
and func_27(func, target_27)
and func_28(vp_len_1586, vs_1645, target_28)
and func_29(vs_1645, target_39, target_29)
and func_30(vkey_state_1584, vp_len_1586, vs_1645, target_30)
and func_31(vp_len_1586, vs_1645, target_31)
and func_32(vg_len_1586, vs_1645, target_32)
and func_33(vs_1645, target_40, target_33)
and func_36(vkey_state_1584, target_36)
and func_37(vsession_1584, vret_1587, target_37)
and func_38(vkey_state_1584, target_38)
and func_39(vkey_state_1584, vp_len_1586, vs_1645, target_39)
and func_40(vkey_state_1584, vg_len_1586, vs_1645, target_40)
and func_42(vsession_1584, vkey_state_1584, vp_len_1586, vret_1587, target_42)
and vsession_1584.getType().hasName("LIBSSH2_SESSION *")
and vkey_state_1584.getType().hasName("key_exchange_state_low_t *")
and vp_len_1586.getType().hasName("unsigned long")
and vg_len_1586.getType().hasName("unsigned long")
and vret_1587.getType().hasName("int")
and vs_1645.getType().hasName("unsigned char *")
and vsession_1584.getParentScope+() = func
and vkey_state_1584.getParentScope+() = func
and vp_len_1586.getParentScope+() = func
and vg_len_1586.getParentScope+() = func
and vret_1587.getParentScope+() = func
and vs_1645.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
