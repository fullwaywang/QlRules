/**
 * @name openssl-98624776c4d501c8badd6f772ab7048ac9191cb9-append_ia5
 * @id cpp/openssl/98624776c4d501c8badd6f772ab7048ac9191cb9/append-ia5
 * @description openssl-98624776c4d501c8badd6f772ab7048ac9191cb9-append_ia5 CVE-2021-3712
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vemail_525) {
	exists(FunctionCall target_0 |
		target_0.getTarget().hasName("CRYPTO_strdup")
		and not target_0.getTarget().hasName("CRYPTO_strndup")
		and target_0.getArgument(0).(PointerFieldAccess).getTarget().getName()="data"
		and target_0.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vemail_525
		and target_0.getArgument(1) instanceof StringLiteral
		and target_0.getArgument(2) instanceof Literal)
}

predicate func_3(Parameter vemail_525) {
	exists(FunctionCall target_3 |
		target_3.getTarget().hasName("memchr")
		and target_3.getArgument(0).(PointerFieldAccess).getTarget().getName()="data"
		and target_3.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vemail_525
		and target_3.getArgument(1).(Literal).getValue()="0"
		and target_3.getArgument(2).(PointerFieldAccess).getTarget().getName()="length"
		and target_3.getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vemail_525)
}

predicate func_6(Parameter vsk_524, Variable vemtmp_527, Function func) {
	exists(IfStmt target_6 |
		target_6.getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getTarget().hasName("OPENSSL_sk_find")
		and target_6.getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(FunctionCall).getTarget().hasName("ossl_check_OPENSSL_STRING_sk_type")
		and target_6.getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(FunctionCall).getArgument(0).(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vsk_524
		and target_6.getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(1).(FunctionCall).getTarget().hasName("ossl_check_OPENSSL_STRING_type")
		and target_6.getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(1).(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vemtmp_527
		and target_6.getCondition().(EqualityOperation).getAnOperand() instanceof UnaryMinusExpr
		and target_6.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("CRYPTO_free")
		and target_6.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vemtmp_527
		and target_6.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1) instanceof StringLiteral
		and target_6.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2) instanceof Literal
		and target_6.getThen().(BlockStmt).getStmt(1) instanceof ReturnStmt
		and (func.getEntryPoint().(BlockStmt).getStmt(8)=target_6 or func.getEntryPoint().(BlockStmt).getStmt(8).getFollowingStmt()=target_6))
}

predicate func_9(Parameter vsk_524, Variable vemtmp_527, Function func) {
	exists(IfStmt target_9 |
		target_9.getCondition() instanceof NotExpr
		and target_9.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("CRYPTO_free")
		and target_9.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vemtmp_527
		and target_9.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1) instanceof StringLiteral
		and target_9.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2) instanceof Literal
		and target_9.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("X509_email_free")
		and target_9.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vsk_524
		and target_9.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vsk_524
		and target_9.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_9.getThen().(BlockStmt).getStmt(3).(ReturnStmt).getExpr().(Literal).getValue()="0"
		and (func.getEntryPoint().(BlockStmt).getStmt(9)=target_9 or func.getEntryPoint().(BlockStmt).getStmt(9).getFollowingStmt()=target_9))
}

predicate func_11(Function func) {
	exists(ReturnStmt target_11 |
		target_11.getExpr().(Literal).getValue()="1"
		and (func.getEntryPoint().(BlockStmt).getStmt(10)=target_11 or func.getEntryPoint().(BlockStmt).getStmt(10).getFollowingStmt()=target_11))
}

predicate func_12(Parameter vemail_525) {
	exists(PointerFieldAccess target_12 |
		target_12.getTarget().getName()="data"
		and target_12.getQualifier().(VariableAccess).getTarget()=vemail_525)
}

predicate func_13(Parameter vemail_525) {
	exists(PointerFieldAccess target_13 |
		target_13.getTarget().getName()="length"
		and target_13.getQualifier().(VariableAccess).getTarget()=vemail_525)
}

predicate func_15(Parameter vsk_524, Parameter vemail_525) {
	exists(UnaryMinusExpr target_15 |
		target_15.getValue()="-1"
		and target_15.getParent().(NEExpr).getAnOperand().(FunctionCall).getTarget().hasName("OPENSSL_sk_find")
		and target_15.getParent().(NEExpr).getAnOperand().(FunctionCall).getArgument(0).(FunctionCall).getTarget().hasName("ossl_check_OPENSSL_STRING_sk_type")
		and target_15.getParent().(NEExpr).getAnOperand().(FunctionCall).getArgument(0).(FunctionCall).getArgument(0).(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vsk_524
		and target_15.getParent().(NEExpr).getAnOperand().(FunctionCall).getArgument(1).(FunctionCall).getTarget().hasName("ossl_check_OPENSSL_STRING_type")
		and target_15.getParent().(NEExpr).getAnOperand().(FunctionCall).getArgument(1).(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="data"
		and target_15.getParent().(NEExpr).getAnOperand().(FunctionCall).getArgument(1).(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vemail_525
		and target_15.getParent().(NEExpr).getParent().(IfStmt).getThen().(ReturnStmt).getExpr().(Literal).getValue()="1")
}

predicate func_21(Parameter vsk_524, Variable vemtmp_527) {
	exists(LogicalOrExpr target_21 |
		target_21.getAnOperand() instanceof EqualityOperation
		and target_21.getAnOperand() instanceof NotExpr
		and target_21.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("CRYPTO_free")
		and target_21.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vemtmp_527
		and target_21.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1) instanceof StringLiteral
		and target_21.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2) instanceof Literal
		and target_21.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("X509_email_free")
		and target_21.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vsk_524)
}

predicate func_22(Function func) {
	exists(LogicalOrExpr target_22 |
		target_22.getAnOperand() instanceof NotExpr
		and target_22.getAnOperand() instanceof NotExpr
		and target_22.getParent().(IfStmt).getThen().(ReturnStmt).getExpr().(Literal).getValue()="1"
		and target_22.getEnclosingFunction() = func)
}

predicate func_23(Variable vemtmp_527) {
	exists(AssignExpr target_23 |
		target_23.getLValue().(VariableAccess).getTarget()=vemtmp_527
		and target_23.getRValue() instanceof FunctionCall)
}

predicate func_24(Variable vemtmp_527) {
	exists(FunctionCall target_24 |
		target_24.getTarget().hasName("CRYPTO_free")
		and target_24.getArgument(0).(VariableAccess).getTarget()=vemtmp_527
		and target_24.getArgument(1) instanceof StringLiteral
		and target_24.getArgument(2) instanceof Literal)
}

from Function func, Parameter vsk_524, Parameter vemail_525, Variable vemtmp_527
where
func_0(vemail_525)
and not func_3(vemail_525)
and not func_6(vsk_524, vemtmp_527, func)
and not func_9(vsk_524, vemtmp_527, func)
and not func_11(func)
and func_12(vemail_525)
and func_13(vemail_525)
and func_15(vsk_524, vemail_525)
and func_21(vsk_524, vemtmp_527)
and vsk_524.getType().hasName("stack_st_OPENSSL_STRING **")
and vemail_525.getType().hasName("const ASN1_IA5STRING *")
and func_22(func)
and func_23(vemtmp_527)
and vemtmp_527.getType().hasName("char *")
and func_24(vemtmp_527)
and vsk_524.getParentScope+() = func
and vemail_525.getParentScope+() = func
and vemtmp_527.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
