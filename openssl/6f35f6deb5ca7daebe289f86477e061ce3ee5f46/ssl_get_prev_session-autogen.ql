/**
 * @name openssl-6f35f6deb5ca7daebe289f86477e061ce3ee5f46-ssl_get_prev_session
 * @id cpp/openssl/6f35f6deb5ca7daebe289f86477e061ce3ee5f46/ssl-get-prev-session
 * @description openssl-6f35f6deb5ca7daebe289f86477e061ce3ee5f46-ssl/ssl_sess.c-ssl_get_prev_session CVE-2016-2177
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vlen_593, Parameter vlimit_594, Parameter vsession_id_593, BlockStmt target_5, EqualityOperation target_6, ExprStmt target_7) {
	exists(RelationalOperation target_0 |
		 (target_0 instanceof GTExpr or target_0 instanceof LTExpr)
		and target_0.getLesserOperand().(PointerArithmeticOperation).getLeftOperand().(VariableAccess).getTarget()=vlimit_594
		and target_0.getLesserOperand().(PointerArithmeticOperation).getRightOperand().(VariableAccess).getTarget()=vsession_id_593
		and target_0.getGreaterOperand().(VariableAccess).getTarget()=vlen_593
		and target_0.getParent().(IfStmt).getThen()=target_5
		and target_0.getGreaterOperand().(VariableAccess).getLocation().isBefore(target_6.getAnOperand().(VariableAccess).getLocation())
		and target_0.getLesserOperand().(PointerArithmeticOperation).getLeftOperand().(VariableAccess).getLocation().isBefore(target_7.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(VariableAccess).getLocation()))
}

predicate func_1(Parameter vsession_id_593, VariableAccess target_1) {
		target_1.getTarget()=vsession_id_593
}

predicate func_2(Parameter vlen_593, VariableAccess target_2) {
		target_2.getTarget()=vlen_593
}

predicate func_3(Parameter vlimit_594, BlockStmt target_5, VariableAccess target_3) {
		target_3.getTarget()=vlimit_594
		and target_3.getParent().(GTExpr).getGreaterOperand() instanceof PointerArithmeticOperation
		and target_3.getParent().(GTExpr).getParent().(IfStmt).getThen()=target_5
}

predicate func_4(Parameter vlen_593, Parameter vlimit_594, Parameter vsession_id_593, BlockStmt target_5, RelationalOperation target_4) {
		 (target_4 instanceof GTExpr or target_4 instanceof LTExpr)
		and target_4.getGreaterOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vsession_id_593
		and target_4.getGreaterOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vlen_593
		and target_4.getLesserOperand().(VariableAccess).getTarget()=vlimit_594
		and target_4.getParent().(IfStmt).getThen()=target_5
}

predicate func_5(BlockStmt target_5) {
		target_5.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="1"
		and target_5.getStmt(1).(GotoStmt).toString() = "goto ..."
		and target_5.getStmt(1).(GotoStmt).getName() ="err"
}

predicate func_6(Parameter vlen_593, EqualityOperation target_6) {
		target_6.getAnOperand().(VariableAccess).getTarget()=vlen_593
		and target_6.getAnOperand().(Literal).getValue()="0"
}

predicate func_7(Parameter vlen_593, Parameter vlimit_594, Parameter vsession_id_593, ExprStmt target_7) {
		target_7.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("tls1_process_ticket")
		and target_7.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vsession_id_593
		and target_7.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vlen_593
		and target_7.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vlimit_594
}

from Function func, Parameter vlen_593, Parameter vlimit_594, Parameter vsession_id_593, VariableAccess target_1, VariableAccess target_2, VariableAccess target_3, RelationalOperation target_4, BlockStmt target_5, EqualityOperation target_6, ExprStmt target_7
where
not func_0(vlen_593, vlimit_594, vsession_id_593, target_5, target_6, target_7)
and func_1(vsession_id_593, target_1)
and func_2(vlen_593, target_2)
and func_3(vlimit_594, target_5, target_3)
and func_4(vlen_593, vlimit_594, vsession_id_593, target_5, target_4)
and func_5(target_5)
and func_6(vlen_593, target_6)
and func_7(vlen_593, vlimit_594, vsession_id_593, target_7)
and vlen_593.getType().hasName("int")
and vlimit_594.getType().hasName("const unsigned char *")
and vsession_id_593.getType().hasName("unsigned char *")
and vlen_593.getParentScope+() = func
and vlimit_594.getParentScope+() = func
and vsession_id_593.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
