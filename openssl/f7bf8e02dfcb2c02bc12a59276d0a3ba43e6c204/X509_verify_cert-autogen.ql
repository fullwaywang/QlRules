/**
 * @name openssl-f7bf8e02dfcb2c02bc12a59276d0a3ba43e6c204-X509_verify_cert
 * @id cpp/openssl/f7bf8e02dfcb2c02bc12a59276d0a3ba43e6c204/X509-verify-cert
 * @description openssl-f7bf8e02dfcb2c02bc12a59276d0a3ba43e6c204-crypto/x509/x509_vfy.c-X509_verify_cert CVE-2015-1793
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_3(Variable vnum_158, ExprStmt target_8, ExprStmt target_9, Function func) {
	exists(ExprStmt target_3 |
		target_3.getExpr().(AssignExpr).getLValue().(VariableAccess).getType().hasName("int")
		and target_3.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vnum_158
		and (func.getEntryPoint().(BlockStmt).getStmt(15)=target_3 or func.getEntryPoint().(BlockStmt).getStmt(15).getFollowingStmt()=target_3)
		and target_8.getExpr().(PostfixIncrExpr).getOperand().(VariableAccess).getLocation().isBefore(target_3.getExpr().(AssignExpr).getRValue().(VariableAccess).getLocation())
		and target_3.getExpr().(AssignExpr).getRValue().(VariableAccess).getLocation().isBefore(target_9.getExpr().(PostfixDecrExpr).getOperand().(VariableAccess).getLocation()))
}

predicate func_4(Parameter vctx_152, Variable vx_154, ConditionalExpr target_10, ConditionalExpr target_11, ExprStmt target_7, ExprStmt target_12, Function func) {
	exists(DoStmt target_4 |
		target_4.getCondition().(VariableAccess).getType().hasName("int")
		and target_4.getStmt().(BlockStmt).getStmt(0) instanceof ExprStmt
		and target_4.getStmt().(BlockStmt).getStmt(1) instanceof ExprStmt
		and target_4.getStmt().(BlockStmt).getStmt(2).(IfStmt).getCondition().(VariableCall).getExpr().(PointerFieldAccess).getTarget().getName()="check_issued"
		and target_4.getStmt().(BlockStmt).getStmt(2).(IfStmt).getCondition().(VariableCall).getExpr().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctx_152
		and target_4.getStmt().(BlockStmt).getStmt(2).(IfStmt).getCondition().(VariableCall).getArgument(0).(VariableAccess).getTarget()=vctx_152
		and target_4.getStmt().(BlockStmt).getStmt(2).(IfStmt).getCondition().(VariableCall).getArgument(1).(VariableAccess).getTarget()=vx_154
		and target_4.getStmt().(BlockStmt).getStmt(2).(IfStmt).getCondition().(VariableCall).getArgument(2).(VariableAccess).getTarget()=vx_154
		and target_4.getStmt().(BlockStmt).getStmt(2).(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getTarget().hasName("sk_num")
		and target_4.getStmt().(BlockStmt).getStmt(2).(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="1"
		and target_4.getStmt().(BlockStmt).getStmt(3).(BlockStmt).getStmt(0).(ForStmt).getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(BreakStmt).toString() = "break;"
		and target_4.getStmt().(BlockStmt).getStmt(3).(BlockStmt).getStmt(0).(ForStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(BreakStmt).toString() = "break;"
		and target_4.getStmt().(BlockStmt).getStmt(3).(BlockStmt).getStmt(0).(ForStmt).getStmt().(BlockStmt).getStmt(4).(IfStmt).getThen().(BreakStmt).toString() = "break;"
		and target_4.getStmt().(BlockStmt).getStmt(3).(BlockStmt).getStmt(1).(LabelStmt).toString() = "label ...:"
		and target_4.getStmt().(BlockStmt).getStmt(4).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getType().hasName("int")
		and target_4.getStmt().(BlockStmt).getStmt(4).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_4.getStmt().(BlockStmt).getStmt(5).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getType().hasName("int")
		and target_4.getStmt().(BlockStmt).getStmt(5).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="last_untrusted"
		and target_4.getStmt().(BlockStmt).getStmt(5).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctx_152
		and target_4.getStmt().(BlockStmt).getStmt(5).(IfStmt).getThen().(BlockStmt).getStmt(0).(BlockStmt).getStmt(1).(LabelStmt).toString() = "label ...:"
		and (func.getEntryPoint().(BlockStmt).getStmt(16)=target_4 or func.getEntryPoint().(BlockStmt).getStmt(16).getFollowingStmt()=target_4)
		and target_10.getThen().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_4.getStmt().(BlockStmt).getStmt(2).(IfStmt).getCondition().(VariableCall).getExpr().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_4.getStmt().(BlockStmt).getStmt(2).(IfStmt).getCondition().(VariableCall).getExpr().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_11.getThen().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_7.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_4.getStmt().(BlockStmt).getStmt(2).(IfStmt).getCondition().(VariableCall).getArgument(1).(VariableAccess).getLocation())
		and target_4.getStmt().(BlockStmt).getStmt(2).(IfStmt).getCondition().(VariableCall).getArgument(1).(VariableAccess).getLocation().isBefore(target_12.getExpr().(AssignExpr).getRValue().(VariableCall).getArgument(2).(VariableAccess).getLocation()))
}

/*predicate func_5(EqualityOperation target_13, Function func) {
	exists(ExprStmt target_5 |
		target_5.getExpr().(PostfixDecrExpr).getOperand().(VariableAccess).getType().hasName("int")
		and target_5.getParent().(BlockStmt).getParent().(IfStmt).getElse().(BlockStmt).getStmt(3)=target_5
		and target_5.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_13
		and target_5.getEnclosingFunction() = func)
}

*/
predicate func_6(Parameter vctx_152, Variable vi_157, Function func, ExprStmt target_6) {
		target_6.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vi_157
		and target_6.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("sk_num")
		and target_6.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(ConditionalExpr).getCondition().(Literal).getValue()="1"
		and target_6.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(ConditionalExpr).getThen().(PointerFieldAccess).getTarget().getName()="chain"
		and target_6.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(ConditionalExpr).getThen().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctx_152
		and target_6.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(ConditionalExpr).getElse().(Literal).getValue()="0"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_6
}

predicate func_7(Parameter vctx_152, Variable vx_154, Variable vi_157, Function func, ExprStmt target_7) {
		target_7.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vx_154
		and target_7.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("sk_value")
		and target_7.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(ConditionalExpr).getCondition().(Literal).getValue()="1"
		and target_7.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(ConditionalExpr).getThen().(PointerFieldAccess).getTarget().getName()="chain"
		and target_7.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(ConditionalExpr).getThen().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctx_152
		and target_7.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(ConditionalExpr).getElse().(Literal).getValue()="0"
		and target_7.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(SubExpr).getLeftOperand().(VariableAccess).getTarget()=vi_157
		and target_7.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(SubExpr).getRightOperand().(Literal).getValue()="1"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_7
}

predicate func_8(Variable vnum_158, ExprStmt target_8) {
		target_8.getExpr().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vnum_158
}

predicate func_9(Variable vnum_158, ExprStmt target_9) {
		target_9.getExpr().(PostfixDecrExpr).getOperand().(VariableAccess).getTarget()=vnum_158
}

predicate func_10(Parameter vctx_152, ConditionalExpr target_10) {
		target_10.getCondition().(Literal).getValue()="1"
		and target_10.getThen().(PointerFieldAccess).getTarget().getName()="chain"
		and target_10.getThen().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctx_152
		and target_10.getElse().(Literal).getValue()="0"
}

predicate func_11(Parameter vctx_152, ConditionalExpr target_11) {
		target_11.getCondition().(Literal).getValue()="1"
		and target_11.getThen().(PointerFieldAccess).getTarget().getName()="chain"
		and target_11.getThen().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctx_152
		and target_11.getElse().(Literal).getValue()="0"
}

predicate func_12(Parameter vctx_152, Variable vx_154, ExprStmt target_12) {
		target_12.getExpr().(AssignExpr).getRValue().(VariableCall).getExpr().(PointerFieldAccess).getTarget().getName()="get_issuer"
		and target_12.getExpr().(AssignExpr).getRValue().(VariableCall).getExpr().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctx_152
		and target_12.getExpr().(AssignExpr).getRValue().(VariableCall).getArgument(1).(VariableAccess).getTarget()=vctx_152
		and target_12.getExpr().(AssignExpr).getRValue().(VariableCall).getArgument(2).(VariableAccess).getTarget()=vx_154
}

predicate func_13(Parameter vctx_152, EqualityOperation target_13) {
		target_13.getAnOperand().(FunctionCall).getTarget().hasName("sk_num")
		and target_13.getAnOperand().(FunctionCall).getArgument(0).(ConditionalExpr).getCondition().(Literal).getValue()="1"
		and target_13.getAnOperand().(FunctionCall).getArgument(0).(ConditionalExpr).getThen().(PointerFieldAccess).getTarget().getName()="chain"
		and target_13.getAnOperand().(FunctionCall).getArgument(0).(ConditionalExpr).getThen().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctx_152
		and target_13.getAnOperand().(FunctionCall).getArgument(0).(ConditionalExpr).getElse().(Literal).getValue()="0"
		and target_13.getAnOperand().(Literal).getValue()="1"
}

from Function func, Variable vnum_158, Parameter vctx_152, Variable vx_154, Variable vi_157, ExprStmt target_6, ExprStmt target_7, ExprStmt target_8, ExprStmt target_9, ConditionalExpr target_10, ConditionalExpr target_11, ExprStmt target_12, EqualityOperation target_13
where
not func_3(vnum_158, target_8, target_9, func)
and not func_4(vctx_152, vx_154, target_10, target_11, target_7, target_12, func)
and func_6(vctx_152, vi_157, func, target_6)
and func_7(vctx_152, vx_154, vi_157, func, target_7)
and func_8(vnum_158, target_8)
and func_9(vnum_158, target_9)
and func_10(vctx_152, target_10)
and func_11(vctx_152, target_11)
and func_12(vctx_152, vx_154, target_12)
and func_13(vctx_152, target_13)
and vnum_158.getType().hasName("int")
and vctx_152.getType().hasName("X509_STORE_CTX *")
and vx_154.getType().hasName("X509 *")
and vi_157.getType().hasName("int")
and vnum_158.getParentScope+() = func
and vctx_152.getParentScope+() = func
and vx_154.getParentScope+() = func
and vi_157.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
