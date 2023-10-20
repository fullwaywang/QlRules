/**
 * @name libtpms-324dbb4c27ae789c73b69dbf4611242267919dd4-CryptParameterDecryption
 * @id cpp/libtpms/324dbb4c27ae789c73b69dbf4611242267919dd4/CryptParameterDecryption
 * @description libtpms-324dbb4c27ae789c73b69dbf4611242267919dd4-src/tpm2/CryptUtil.c-CryptParameterDecryption CVE-2023-1017
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vbufferSize_818, Parameter vleadingSizeInByte_819, BlockStmt target_5, EqualityOperation target_4) {
	exists(RelationalOperation target_0 |
		 (target_0 instanceof GTExpr or target_0 instanceof LTExpr)
		and target_0.getGreaterOperand().(VariableAccess).getTarget()=vleadingSizeInByte_819
		and target_0.getLesserOperand().(VariableAccess).getTarget()=vbufferSize_818
		and target_0.getParent().(IfStmt).getThen()=target_5
		and target_0.getGreaterOperand().(VariableAccess).getLocation().isBefore(target_4.getAnOperand().(VariableAccess).getLocation()))
}

predicate func_1(EqualityOperation target_4, Function func) {
	exists(ReturnStmt target_1 |
		target_1.getExpr().(AddExpr).getValue()="154"
		and target_1.getParent().(IfStmt).getCondition()=target_4
		and target_1.getEnclosingFunction() = func)
}

predicate func_2(Parameter vbufferSize_818, Parameter vbuffer_822, Variable vcipherSize_832, Variable v__func__, RelationalOperation target_6, ExprStmt target_7, Function func) {
	exists(IfStmt target_2 |
		target_2.getCondition() instanceof EqualityOperation
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vcipherSize_832
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("ByteArrayToUint16")
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vbuffer_822
		and target_2.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vbuffer_822
		and target_2.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(AddressOfExpr).getOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vbuffer_822
		and target_2.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(AddressOfExpr).getOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="2"
		and target_2.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignSubExpr).getLValue().(VariableAccess).getTarget()=vbufferSize_818
		and target_2.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignSubExpr).getRValue().(Literal).getValue()="2"
		and target_2.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("TpmFail")
		and target_2.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=v__func__
		and target_2.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1) instanceof Literal
		and target_2.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2) instanceof Literal
		and (func.getEntryPoint().(BlockStmt).getStmt(5)=target_2 or func.getEntryPoint().(BlockStmt).getStmt(5).getFollowingStmt()=target_2)
		and target_2.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignSubExpr).getLValue().(VariableAccess).getLocation().isBefore(target_6.getLesserOperand().(VariableAccess).getLocation())
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_7.getExpr().(FunctionCall).getArgument(5).(VariableAccess).getLocation()))
}

/*predicate func_3(Parameter vbufferSize_818, EqualityOperation target_4, RelationalOperation target_6) {
	exists(ExprStmt target_3 |
		target_3.getExpr().(AssignSubExpr).getLValue().(VariableAccess).getTarget()=vbufferSize_818
		and target_3.getExpr().(AssignSubExpr).getRValue().(Literal).getValue()="2"
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(2)=target_3
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_4
		and target_3.getExpr().(AssignSubExpr).getLValue().(VariableAccess).getLocation().isBefore(target_6.getLesserOperand().(VariableAccess).getLocation()))
}

*/
predicate func_4(Parameter vleadingSizeInByte_819, BlockStmt target_5, EqualityOperation target_4) {
		target_4.getAnOperand().(VariableAccess).getTarget()=vleadingSizeInByte_819
		and target_4.getAnOperand().(Literal).getValue()="2"
		and target_4.getParent().(IfStmt).getThen()=target_5
}

predicate func_5(Parameter vbuffer_822, Variable vcipherSize_832, BlockStmt target_5) {
		target_5.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vcipherSize_832
		and target_5.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("ByteArrayToUint16")
		and target_5.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vbuffer_822
		and target_5.getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vbuffer_822
		and target_5.getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(AddressOfExpr).getOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vbuffer_822
		and target_5.getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(AddressOfExpr).getOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="2"
}

predicate func_6(Parameter vbufferSize_818, Variable vcipherSize_832, RelationalOperation target_6) {
		 (target_6 instanceof GTExpr or target_6 instanceof LTExpr)
		and target_6.getGreaterOperand().(VariableAccess).getTarget()=vcipherSize_832
		and target_6.getLesserOperand().(VariableAccess).getTarget()=vbufferSize_818
}

predicate func_7(Parameter vbuffer_822, Variable vcipherSize_832, ExprStmt target_7) {
		target_7.getExpr().(FunctionCall).getTarget().hasName("CryptXORObfuscation")
		and target_7.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="authHashAlg"
		and target_7.getExpr().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(ValueFieldAccess).getTarget().getName()="b"
		and target_7.getExpr().(FunctionCall).getArgument(3).(AddressOfExpr).getOperand().(ValueFieldAccess).getTarget().getName()="b"
		and target_7.getExpr().(FunctionCall).getArgument(3).(AddressOfExpr).getOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="nonceTPM"
		and target_7.getExpr().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vcipherSize_832
		and target_7.getExpr().(FunctionCall).getArgument(5).(VariableAccess).getTarget()=vbuffer_822
}

from Function func, Parameter vbufferSize_818, Parameter vleadingSizeInByte_819, Parameter vbuffer_822, Variable vcipherSize_832, Variable v__func__, EqualityOperation target_4, BlockStmt target_5, RelationalOperation target_6, ExprStmt target_7
where
not func_0(vbufferSize_818, vleadingSizeInByte_819, target_5, target_4)
and not func_1(target_4, func)
and not func_2(vbufferSize_818, vbuffer_822, vcipherSize_832, v__func__, target_6, target_7, func)
and func_4(vleadingSizeInByte_819, target_5, target_4)
and func_5(vbuffer_822, vcipherSize_832, target_5)
and func_6(vbufferSize_818, vcipherSize_832, target_6)
and func_7(vbuffer_822, vcipherSize_832, target_7)
and vbufferSize_818.getType().hasName("UINT32")
and vleadingSizeInByte_819.getType().hasName("UINT16")
and vbuffer_822.getType().hasName("BYTE *")
and vcipherSize_832.getType().hasName("UINT32")
and v__func__.getType() instanceof ArrayType
and vbufferSize_818.getParentScope+() = func
and vleadingSizeInByte_819.getParentScope+() = func
and vbuffer_822.getParentScope+() = func
and vcipherSize_832.getParentScope+() = func
and not v__func__.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
