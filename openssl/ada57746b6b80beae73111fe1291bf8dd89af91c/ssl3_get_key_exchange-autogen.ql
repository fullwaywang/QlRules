/**
 * @name openssl-ada57746b6b80beae73111fe1291bf8dd89af91c-ssl3_get_key_exchange
 * @id cpp/openssl/ada57746b6b80beae73111fe1291bf8dd89af91c/ssl3-get-key-exchange
 * @description openssl-ada57746b6b80beae73111fe1291bf8dd89af91c-ssl/s3_clnt.c-ssl3_get_key_exchange CVE-2015-1794
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vdh_1374, BitwiseAndExpr target_3, NotExpr target_4, NotExpr target_5) {
	exists(IfStmt target_0 |
		target_0.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="top"
		and target_0.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="p"
		and target_0.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdh_1374
		and target_0.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ERR_put_error")
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0) instanceof Literal
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1) instanceof Literal
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2) instanceof Literal
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3) instanceof StringLiteral
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(4) instanceof Literal
		and target_0.getThen().(BlockStmt).getStmt(1).(GotoStmt).toString() = "goto ..."
		and target_0.getThen().(BlockStmt).getStmt(1).(GotoStmt).getName() ="f_err"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(8)=target_0
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_3
		and target_4.getOperand().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_5.getOperand().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Variable vdh_1374, BitwiseAndExpr target_3, NotExpr target_5, NotExpr target_6) {
	exists(IfStmt target_1 |
		target_1.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="top"
		and target_1.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="g"
		and target_1.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdh_1374
		and target_1.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ERR_put_error")
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0) instanceof Literal
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1) instanceof Literal
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2) instanceof Literal
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3) instanceof StringLiteral
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(4) instanceof Literal
		and target_1.getThen().(BlockStmt).getStmt(1).(GotoStmt).toString() = "goto ..."
		and target_1.getThen().(BlockStmt).getStmt(1).(GotoStmt).getName() ="f_err"
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(16)=target_1
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_3
		and target_5.getOperand().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_1.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_1.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_6.getOperand().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_2(Variable vdh_1374, BitwiseAndExpr target_3, NotExpr target_6, ExprStmt target_7) {
	exists(IfStmt target_2 |
		target_2.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="top"
		and target_2.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="pub_key"
		and target_2.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdh_1374
		and target_2.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ERR_put_error")
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0) instanceof Literal
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1) instanceof Literal
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2) instanceof Literal
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3) instanceof StringLiteral
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(4) instanceof Literal
		and target_2.getThen().(BlockStmt).getStmt(1).(GotoStmt).toString() = "goto ..."
		and target_2.getThen().(BlockStmt).getStmt(1).(GotoStmt).getName() ="f_err"
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(25)=target_2
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_3
		and target_6.getOperand().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_2.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_2.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_7.getExpr().(AssignExpr).getRValue().(VariableAccess).getLocation()))
}

predicate func_3(BitwiseAndExpr target_3) {
		target_3.getRightOperand().(Literal).getValue()="8"
}

predicate func_4(Variable vdh_1374, NotExpr target_4) {
		target_4.getOperand().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="p"
		and target_4.getOperand().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdh_1374
		and target_4.getOperand().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("BN_bin2bn")
		and target_4.getOperand().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(Literal).getValue()="0"
}

predicate func_5(Variable vdh_1374, NotExpr target_5) {
		target_5.getOperand().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="g"
		and target_5.getOperand().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdh_1374
		and target_5.getOperand().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("BN_bin2bn")
		and target_5.getOperand().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(Literal).getValue()="0"
}

predicate func_6(Variable vdh_1374, NotExpr target_6) {
		target_6.getOperand().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="pub_key"
		and target_6.getOperand().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdh_1374
		and target_6.getOperand().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("BN_bin2bn")
		and target_6.getOperand().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(Literal).getValue()="0"
}

predicate func_7(Variable vdh_1374, ExprStmt target_7) {
		target_7.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="peer_dh_tmp"
		and target_7.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="sess_cert"
		and target_7.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="session"
		and target_7.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vdh_1374
}

from Function func, Variable vdh_1374, BitwiseAndExpr target_3, NotExpr target_4, NotExpr target_5, NotExpr target_6, ExprStmt target_7
where
not func_0(vdh_1374, target_3, target_4, target_5)
and not func_1(vdh_1374, target_3, target_5, target_6)
and not func_2(vdh_1374, target_3, target_6, target_7)
and func_3(target_3)
and func_4(vdh_1374, target_4)
and func_5(vdh_1374, target_5)
and func_6(vdh_1374, target_6)
and func_7(vdh_1374, target_7)
and vdh_1374.getType().hasName("DH *")
and vdh_1374.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
