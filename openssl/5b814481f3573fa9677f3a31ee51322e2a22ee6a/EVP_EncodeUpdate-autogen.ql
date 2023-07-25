/**
 * @name openssl-5b814481f3573fa9677f3a31ee51322e2a22ee6a-EVP_EncodeUpdate
 * @id cpp/openssl/5b814481f3573fa9677f3a31ee51322e2a22ee6a/EVP-EncodeUpdate
 * @description openssl-5b814481f3573fa9677f3a31ee51322e2a22ee6a-crypto/evp/encode.c-EVP_EncodeUpdate CVE-2016-2105
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vinl_151, Parameter vctx_150, BlockStmt target_5, RelationalOperation target_6, ExprStmt target_7, RelationalOperation target_4) {
	exists(RelationalOperation target_0 |
		 (target_0 instanceof GTExpr or target_0 instanceof LTExpr)
		and target_0.getGreaterOperand().(SubExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="length"
		and target_0.getGreaterOperand().(SubExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctx_150
		and target_0.getGreaterOperand().(SubExpr).getRightOperand().(PointerFieldAccess).getTarget().getName()="num"
		and target_0.getGreaterOperand().(SubExpr).getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctx_150
		and target_0.getLesserOperand().(VariableAccess).getTarget()=vinl_151
		and target_0.getParent().(IfStmt).getThen()=target_5
		and target_6.getLesserOperand().(VariableAccess).getLocation().isBefore(target_0.getLesserOperand().(VariableAccess).getLocation())
		and target_0.getLesserOperand().(VariableAccess).getLocation().isBefore(target_7.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getLocation())
		and target_4.getLesserOperand().(AddExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getGreaterOperand().(SubExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vctx_150, PointerFieldAccess target_1) {
		target_1.getTarget().getName()="num"
		and target_1.getQualifier().(VariableAccess).getTarget()=vctx_150
}

predicate func_2(Parameter vctx_150, BlockStmt target_5, PointerFieldAccess target_2) {
		target_2.getTarget().getName()="length"
		and target_2.getQualifier().(VariableAccess).getTarget()=vctx_150
		and target_2.getParent().(LTExpr).getLesserOperand() instanceof AddExpr
		and target_2.getParent().(LTExpr).getParent().(IfStmt).getThen()=target_5
}

predicate func_3(Parameter vinl_151, VariableAccess target_3) {
		target_3.getTarget()=vinl_151
}

predicate func_4(Parameter vinl_151, Parameter vctx_150, BlockStmt target_5, RelationalOperation target_4) {
		 (target_4 instanceof GTExpr or target_4 instanceof LTExpr)
		and target_4.getLesserOperand().(AddExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="num"
		and target_4.getLesserOperand().(AddExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctx_150
		and target_4.getLesserOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vinl_151
		and target_4.getGreaterOperand().(PointerFieldAccess).getTarget().getName()="length"
		and target_4.getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctx_150
		and target_4.getParent().(IfStmt).getThen()=target_5
}

predicate func_5(Parameter vinl_151, Parameter vctx_150, BlockStmt target_5) {
		target_5.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("memcpy")
		and target_5.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="enc_data"
		and target_5.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctx_150
		and target_5.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(ArrayExpr).getArrayOffset().(PointerFieldAccess).getTarget().getName()="num"
		and target_5.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(ArrayExpr).getArrayOffset().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctx_150
		and target_5.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vinl_151
}

predicate func_6(Parameter vinl_151, RelationalOperation target_6) {
		 (target_6 instanceof GEExpr or target_6 instanceof LEExpr)
		and target_6.getLesserOperand().(VariableAccess).getTarget()=vinl_151
		and target_6.getGreaterOperand().(Literal).getValue()="0"
}

predicate func_7(Parameter vinl_151, Parameter vctx_150, ExprStmt target_7) {
		target_7.getExpr().(FunctionCall).getTarget().hasName("memcpy")
		and target_7.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="enc_data"
		and target_7.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctx_150
		and target_7.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(ArrayExpr).getArrayOffset().(PointerFieldAccess).getTarget().getName()="num"
		and target_7.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(ArrayExpr).getArrayOffset().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctx_150
		and target_7.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vinl_151
}

from Function func, Parameter vinl_151, Parameter vctx_150, PointerFieldAccess target_1, PointerFieldAccess target_2, VariableAccess target_3, RelationalOperation target_4, BlockStmt target_5, RelationalOperation target_6, ExprStmt target_7
where
not func_0(vinl_151, vctx_150, target_5, target_6, target_7, target_4)
and func_1(vctx_150, target_1)
and func_2(vctx_150, target_5, target_2)
and func_3(vinl_151, target_3)
and func_4(vinl_151, vctx_150, target_5, target_4)
and func_5(vinl_151, vctx_150, target_5)
and func_6(vinl_151, target_6)
and func_7(vinl_151, vctx_150, target_7)
and vinl_151.getType().hasName("int")
and vctx_150.getType().hasName("EVP_ENCODE_CTX *")
and vinl_151.getParentScope+() = func
and vctx_150.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
