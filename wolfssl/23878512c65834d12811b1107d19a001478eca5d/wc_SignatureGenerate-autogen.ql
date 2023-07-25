/**
 * @name wolfssl-23878512c65834d12811b1107d19a001478eca5d-wc_SignatureGenerate
 * @id cpp/wolfssl/23878512c65834d12811b1107d19a001478eca5d/wc-SignatureGenerate
 * @description wolfssl-23878512c65834d12811b1107d19a001478eca5d-wolfcrypt/src/signature.c-wc_SignatureGenerate CVE-2019-19962
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func, Literal target_0) {
		target_0.getValue()="0"
		and not target_0.getValue()="1"
		and target_0.getParent().(EQExpr).getParent().(LogicalOrExpr).getAnOperand() instanceof EqualityOperation
		and target_0.getEnclosingFunction() = func
}

predicate func_1(Parameter vsig_type_400, Parameter vkey_403, Parameter vkey_len_403, FunctionCall target_1) {
		target_1.getTarget().hasName("wc_SignatureGetSize")
		and not target_1.getTarget().hasName("wc_SignatureGenerate_ex")
		and target_1.getArgument(0).(VariableAccess).getTarget()=vsig_type_400
		and target_1.getArgument(1).(VariableAccess).getTarget()=vkey_403
		and target_1.getArgument(2).(VariableAccess).getTarget()=vkey_len_403
}

predicate func_2(Parameter vhash_type_400, VariableAccess target_2) {
		target_2.getTarget()=vhash_type_400
		and target_2.getParent().(FunctionCall).getParent().(AssignExpr).getRValue() instanceof FunctionCall
}

predicate func_3(Parameter vdata_401, VariableAccess target_3) {
		target_3.getTarget()=vdata_401
		and target_3.getParent().(FunctionCall).getParent().(AssignExpr).getRValue() instanceof FunctionCall
}

predicate func_4(Parameter vdata_len_401, VariableAccess target_4) {
		target_4.getTarget()=vdata_len_401
		and target_4.getParent().(FunctionCall).getParent().(AssignExpr).getRValue() instanceof FunctionCall
}

predicate func_5(Parameter vsig_type_400, VariableAccess target_5) {
		target_5.getTarget()=vsig_type_400
		and target_5.getParent().(FunctionCall).getParent().(AssignExpr).getRValue() instanceof FunctionCall
}

predicate func_6(Parameter vsig_402, VariableAccess target_6) {
		target_6.getTarget()=vsig_402
		and target_6.getParent().(FunctionCall).getParent().(AssignExpr).getRValue() instanceof FunctionCall
}

predicate func_7(Parameter vsig_len_402, VariableAccess target_7) {
		target_7.getTarget()=vsig_len_402
		and target_7.getParent().(FunctionCall).getParent().(AssignExpr).getRValue() instanceof FunctionCall
}

predicate func_8(Parameter vrng_403, VariableAccess target_8) {
		target_8.getTarget()=vrng_403
		and target_8.getParent().(FunctionCall).getParent().(AssignExpr).getRValue() instanceof FunctionCall
}

predicate func_9(Function func, DeclStmt target_9) {
		func.getEntryPoint().(BlockStmt).getAStmt()=target_9
}

predicate func_10(Function func, DeclStmt target_10) {
		func.getEntryPoint().(BlockStmt).getAStmt()=target_10
}

predicate func_11(Function func, DeclStmt target_11) {
		func.getEntryPoint().(BlockStmt).getAStmt()=target_11
}

predicate func_12(Parameter vsig_len_402, Parameter vkey_403, Parameter vkey_len_403, Function func, IfStmt target_12) {
		target_12.getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vsig_len_402
		and target_12.getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_12.getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vsig_len_402
		and target_12.getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(Literal).getValue()="0"
		and target_12.getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vkey_403
		and target_12.getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_12.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vkey_len_403
		and target_12.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(Literal).getValue()="0"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_12
}

predicate func_14(Parameter vsig_len_402, Function func, IfStmt target_14) {
		target_14.getCondition().(RelationalOperation).getLesserOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vsig_len_402
		and target_14.getCondition().(RelationalOperation).getGreaterOperand() instanceof FunctionCall
		and target_14.getThen().(BlockStmt).getStmt(0).(EmptyStmt).toString() = ";"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_14
}

/*predicate func_15(RelationalOperation target_31, Function func, EmptyStmt target_15) {
		target_15.toString() = ";"
		and target_15.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_31
		and target_15.getEnclosingFunction() = func
}

*/
/*predicate func_16(RelationalOperation target_31, Function func, ReturnStmt target_16) {
		target_16.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_31
		and target_16.getEnclosingFunction() = func
}

*/
predicate func_17(Parameter vhash_type_400, Variable vret_405, Function func, ExprStmt target_17) {
		target_17.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vret_405
		and target_17.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("wc_HashGetDigestSize")
		and target_17.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vhash_type_400
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_17
}

predicate func_18(Variable vret_405, Function func, IfStmt target_18) {
		target_18.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vret_405
		and target_18.getCondition().(RelationalOperation).getGreaterOperand().(Literal).getValue()="0"
		and target_18.getThen().(BlockStmt).getStmt(0).(EmptyStmt).toString() = ";"
		and target_18.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(VariableAccess).getTarget()=vret_405
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_18
}

/*predicate func_19(RelationalOperation target_32, Function func, EmptyStmt target_19) {
		target_19.toString() = ";"
		and target_19.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_32
		and target_19.getEnclosingFunction() = func
}

*/
/*predicate func_20(Variable vret_405, RelationalOperation target_32, ExprStmt target_21, ReturnStmt target_20) {
		target_20.getExpr().(VariableAccess).getTarget()=vret_405
		and target_20.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_32
		and target_20.getExpr().(VariableAccess).getLocation().isBefore(target_21.getExpr().(AssignExpr).getRValue().(AssignExpr).getRValue().(VariableAccess).getLocation())
}

*/
predicate func_21(Variable vhash_enc_len_406, Variable vret_405, Variable vhash_len_406, Function func, ExprStmt target_21) {
		target_21.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vhash_enc_len_406
		and target_21.getExpr().(AssignExpr).getRValue().(AssignExpr).getLValue().(VariableAccess).getTarget()=vhash_len_406
		and target_21.getExpr().(AssignExpr).getRValue().(AssignExpr).getRValue().(VariableAccess).getTarget()=vret_405
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_21
}

predicate func_22(Variable vhash_enc_len_406, Parameter vsig_type_400, Function func, IfStmt target_22) {
		target_22.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vsig_type_400
		and target_22.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignAddExpr).getLValue().(VariableAccess).getTarget()=vhash_enc_len_406
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_22
}

/*predicate func_23(Variable vhash_enc_len_406, EqualityOperation target_33, ExprStmt target_23) {
		target_23.getExpr().(AssignAddExpr).getLValue().(VariableAccess).getTarget()=vhash_enc_len_406
		and target_23.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_33
}

*/
predicate func_24(Variable vhash_data_410, Parameter vhash_type_400, Parameter vdata_401, Parameter vdata_len_401, Variable vret_405, Variable vhash_len_406, Function func, ExprStmt target_24) {
		target_24.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vret_405
		and target_24.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("wc_Hash")
		and target_24.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vhash_type_400
		and target_24.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vdata_401
		and target_24.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vdata_len_401
		and target_24.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vhash_data_410
		and target_24.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vhash_len_406
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_24
}

predicate func_25(Parameter vsig_type_400, Variable vret_405, Function func, IfStmt target_25) {
		target_25.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vret_405
		and target_25.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_25.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vsig_type_400
		and target_25.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vret_405
		and target_25.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("wc_SignatureDerEncode")
		and target_25.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vret_405
		and target_25.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_25.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vret_405
		and target_25.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("wc_SignatureGenerateHash")
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_25
}

/*predicate func_26(Variable vhash_enc_len_406, Variable vhash_data_410, Parameter vhash_type_400, Parameter vsig_type_400, Variable vret_405, Variable vhash_len_406, EqualityOperation target_34, IfStmt target_26) {
		target_26.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vsig_type_400
		and target_26.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vret_405
		and target_26.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("wc_SignatureDerEncode")
		and target_26.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vhash_type_400
		and target_26.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vhash_data_410
		and target_26.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vhash_len_406
		and target_26.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vhash_enc_len_406
		and target_26.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_34
}

*/
/*predicate func_27(Variable vhash_enc_len_406, Variable vhash_data_410, Parameter vhash_type_400, Variable vret_405, Variable vhash_len_406, EqualityOperation target_35, ExprStmt target_27) {
		target_27.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vret_405
		and target_27.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("wc_SignatureDerEncode")
		and target_27.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vhash_type_400
		and target_27.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vhash_data_410
		and target_27.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vhash_len_406
		and target_27.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vhash_enc_len_406
		and target_27.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_35
}

*/
/*predicate func_28(Variable vhash_enc_len_406, Variable vhash_data_410, Parameter vhash_type_400, Parameter vsig_type_400, Parameter vsig_402, Parameter vsig_len_402, Parameter vkey_403, Parameter vkey_len_403, Parameter vrng_403, Variable vret_405, EqualityOperation target_34, IfStmt target_28) {
		target_28.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vret_405
		and target_28.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_28.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vret_405
		and target_28.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("wc_SignatureGenerateHash")
		and target_28.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vhash_type_400
		and target_28.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vsig_type_400
		and target_28.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vhash_data_410
		and target_28.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vhash_enc_len_406
		and target_28.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vsig_402
		and target_28.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(5).(VariableAccess).getTarget()=vsig_len_402
		and target_28.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(6).(VariableAccess).getTarget()=vkey_403
		and target_28.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(7).(VariableAccess).getTarget()=vkey_len_403
		and target_28.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(8).(VariableAccess).getTarget()=vrng_403
		and target_28.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_34
}

*/
predicate func_29(Variable vhash_enc_len_406, Variable vhash_data_410, Parameter vhash_type_400, Parameter vsig_type_400, Parameter vsig_402, Parameter vsig_len_402, Parameter vkey_403, Parameter vkey_len_403, Parameter vrng_403, Variable vret_405, EqualityOperation target_36, ExprStmt target_29) {
		target_29.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vret_405
		and target_29.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("wc_SignatureGenerateHash")
		and target_29.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vhash_type_400
		and target_29.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vsig_type_400
		and target_29.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vhash_data_410
		and target_29.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vhash_enc_len_406
		and target_29.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vsig_402
		and target_29.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(5).(VariableAccess).getTarget()=vsig_len_402
		and target_29.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(6).(VariableAccess).getTarget()=vkey_403
		and target_29.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(7).(VariableAccess).getTarget()=vkey_len_403
		and target_29.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(8).(VariableAccess).getTarget()=vrng_403
		and target_29.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_36
}

predicate func_30(Variable vret_405, ExprStmt target_29, Function func, ReturnStmt target_30) {
		target_30.getExpr().(VariableAccess).getTarget()=vret_405
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_30
		and target_29.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_30.getExpr().(VariableAccess).getLocation())
}

predicate func_31(RelationalOperation target_31) {
		 (target_31 instanceof GTExpr or target_31 instanceof LTExpr)
		and target_31.getLesserOperand() instanceof PointerDereferenceExpr
		and target_31.getGreaterOperand() instanceof FunctionCall
}

predicate func_32(Variable vret_405, RelationalOperation target_32) {
		 (target_32 instanceof GTExpr or target_32 instanceof LTExpr)
		and target_32.getLesserOperand().(VariableAccess).getTarget()=vret_405
		and target_32.getGreaterOperand() instanceof Literal
}

predicate func_33(Parameter vsig_type_400, EqualityOperation target_33) {
		target_33.getAnOperand().(VariableAccess).getTarget()=vsig_type_400
		and target_33.getAnOperand() instanceof EnumConstantAccess
}

predicate func_34(Variable vret_405, EqualityOperation target_34) {
		target_34.getAnOperand().(VariableAccess).getTarget()=vret_405
		and target_34.getAnOperand() instanceof Literal
}

predicate func_35(Parameter vsig_type_400, EqualityOperation target_35) {
		target_35.getAnOperand().(VariableAccess).getTarget()=vsig_type_400
		and target_35.getAnOperand() instanceof EnumConstantAccess
}

predicate func_36(Variable vret_405, EqualityOperation target_36) {
		target_36.getAnOperand().(VariableAccess).getTarget()=vret_405
		and target_36.getAnOperand() instanceof Literal
}

from Function func, Variable vhash_enc_len_406, Variable vhash_data_410, Parameter vhash_type_400, Parameter vsig_type_400, Parameter vdata_401, Parameter vdata_len_401, Parameter vsig_402, Parameter vsig_len_402, Parameter vkey_403, Parameter vkey_len_403, Parameter vrng_403, Variable vret_405, Variable vhash_len_406, Literal target_0, FunctionCall target_1, VariableAccess target_2, VariableAccess target_3, VariableAccess target_4, VariableAccess target_5, VariableAccess target_6, VariableAccess target_7, VariableAccess target_8, DeclStmt target_9, DeclStmt target_10, DeclStmt target_11, IfStmt target_12, IfStmt target_14, ExprStmt target_17, IfStmt target_18, ExprStmt target_21, IfStmt target_22, ExprStmt target_24, IfStmt target_25, ExprStmt target_29, ReturnStmt target_30, RelationalOperation target_31, RelationalOperation target_32, EqualityOperation target_33, EqualityOperation target_34, EqualityOperation target_35, EqualityOperation target_36
where
func_0(func, target_0)
and func_1(vsig_type_400, vkey_403, vkey_len_403, target_1)
and func_2(vhash_type_400, target_2)
and func_3(vdata_401, target_3)
and func_4(vdata_len_401, target_4)
and func_5(vsig_type_400, target_5)
and func_6(vsig_402, target_6)
and func_7(vsig_len_402, target_7)
and func_8(vrng_403, target_8)
and func_9(func, target_9)
and func_10(func, target_10)
and func_11(func, target_11)
and func_12(vsig_len_402, vkey_403, vkey_len_403, func, target_12)
and func_14(vsig_len_402, func, target_14)
and func_17(vhash_type_400, vret_405, func, target_17)
and func_18(vret_405, func, target_18)
and func_21(vhash_enc_len_406, vret_405, vhash_len_406, func, target_21)
and func_22(vhash_enc_len_406, vsig_type_400, func, target_22)
and func_24(vhash_data_410, vhash_type_400, vdata_401, vdata_len_401, vret_405, vhash_len_406, func, target_24)
and func_25(vsig_type_400, vret_405, func, target_25)
and func_29(vhash_enc_len_406, vhash_data_410, vhash_type_400, vsig_type_400, vsig_402, vsig_len_402, vkey_403, vkey_len_403, vrng_403, vret_405, target_36, target_29)
and func_30(vret_405, target_29, func, target_30)
and func_31(target_31)
and func_32(vret_405, target_32)
and func_33(vsig_type_400, target_33)
and func_34(vret_405, target_34)
and func_35(vsig_type_400, target_35)
and func_36(vret_405, target_36)
and vhash_enc_len_406.getType().hasName("word32")
and vhash_data_410.getType().hasName("byte[98]")
and vhash_type_400.getType().hasName("wc_HashType")
and vsig_type_400.getType().hasName("wc_SignatureType")
and vdata_401.getType().hasName("const byte *")
and vdata_len_401.getType().hasName("word32")
and vsig_402.getType().hasName("byte *")
and vsig_len_402.getType().hasName("word32 *")
and vkey_403.getType().hasName("const void *")
and vkey_len_403.getType().hasName("word32")
and vrng_403.getType().hasName("WC_RNG *")
and vret_405.getType().hasName("int")
and vhash_len_406.getType().hasName("word32")
and vhash_enc_len_406.getParentScope+() = func
and vhash_data_410.getParentScope+() = func
and vhash_type_400.getParentScope+() = func
and vsig_type_400.getParentScope+() = func
and vdata_401.getParentScope+() = func
and vdata_len_401.getParentScope+() = func
and vsig_402.getParentScope+() = func
and vsig_len_402.getParentScope+() = func
and vkey_403.getParentScope+() = func
and vkey_len_403.getParentScope+() = func
and vrng_403.getParentScope+() = func
and vret_405.getParentScope+() = func
and vhash_len_406.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
