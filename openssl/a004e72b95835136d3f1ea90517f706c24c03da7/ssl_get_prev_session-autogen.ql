/**
 * @name openssl-a004e72b95835136d3f1ea90517f706c24c03da7-ssl_get_prev_session
 * @id cpp/openssl/a004e72b95835136d3f1ea90517f706c24c03da7/ssl-get-prev-session
 * @description openssl-a004e72b95835136d3f1ea90517f706c24c03da7-ssl/ssl_sess.c-ssl_get_prev_session CVE-2016-2177
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vlen_564, Parameter vlimit_565, Parameter vsession_id_564, BlockStmt target_5, EqualityOperation target_6, ExprStmt target_7) {
	exists(RelationalOperation target_0 |
		 (target_0 instanceof GTExpr or target_0 instanceof LTExpr)
		and target_0.getLesserOperand().(PointerArithmeticOperation).getLeftOperand().(VariableAccess).getTarget()=vlimit_565
		and target_0.getLesserOperand().(PointerArithmeticOperation).getRightOperand().(VariableAccess).getTarget()=vsession_id_564
		and target_0.getGreaterOperand().(VariableAccess).getTarget()=vlen_564
		and target_0.getParent().(IfStmt).getThen()=target_5
		and target_0.getGreaterOperand().(VariableAccess).getLocation().isBefore(target_6.getAnOperand().(VariableAccess).getLocation())
		and target_0.getLesserOperand().(PointerArithmeticOperation).getLeftOperand().(VariableAccess).getLocation().isBefore(target_7.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(VariableAccess).getLocation()))
}

predicate func_1(Parameter vsession_id_564, VariableAccess target_1) {
		target_1.getTarget()=vsession_id_564
}

predicate func_2(Parameter vlen_564, VariableAccess target_2) {
		target_2.getTarget()=vlen_564
}

predicate func_3(Parameter vlimit_565, BlockStmt target_5, VariableAccess target_3) {
		target_3.getTarget()=vlimit_565
		and target_3.getParent().(GTExpr).getGreaterOperand() instanceof PointerArithmeticOperation
		and target_3.getParent().(GTExpr).getParent().(IfStmt).getThen()=target_5
}

predicate func_4(Parameter vlen_564, Parameter vlimit_565, Parameter vsession_id_564, BlockStmt target_5, RelationalOperation target_4) {
		 (target_4 instanceof GTExpr or target_4 instanceof LTExpr)
		and target_4.getGreaterOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vsession_id_564
		and target_4.getGreaterOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vlen_564
		and target_4.getLesserOperand().(VariableAccess).getTarget()=vlimit_565
		and target_4.getParent().(IfStmt).getThen()=target_5
}

predicate func_5(BlockStmt target_5) {
		target_5.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="1"
		and target_5.getStmt(1).(GotoStmt).toString() = "goto ..."
		and target_5.getStmt(1).(GotoStmt).getName() ="err"
}

predicate func_6(Parameter vlen_564, EqualityOperation target_6) {
		target_6.getAnOperand().(VariableAccess).getTarget()=vlen_564
		and target_6.getAnOperand().(Literal).getValue()="0"
}

predicate func_7(Parameter vlen_564, Parameter vlimit_565, Parameter vsession_id_564, ExprStmt target_7) {
		target_7.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("tls1_process_ticket")
		and target_7.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vsession_id_564
		and target_7.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vlen_564
		and target_7.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vlimit_565
}

from Function func, Parameter vlen_564, Parameter vlimit_565, Parameter vsession_id_564, VariableAccess target_1, VariableAccess target_2, VariableAccess target_3, RelationalOperation target_4, BlockStmt target_5, EqualityOperation target_6, ExprStmt target_7
where
not func_0(vlen_564, vlimit_565, vsession_id_564, target_5, target_6, target_7)
and func_1(vsession_id_564, target_1)
and func_2(vlen_564, target_2)
and func_3(vlimit_565, target_5, target_3)
and func_4(vlen_564, vlimit_565, vsession_id_564, target_5, target_4)
and func_5(target_5)
and func_6(vlen_564, target_6)
and func_7(vlen_564, vlimit_565, vsession_id_564, target_7)
and vlen_564.getType().hasName("int")
and vlimit_565.getType().hasName("const unsigned char *")
and vsession_id_564.getType().hasName("unsigned char *")
and vlen_564.getParentScope+() = func
and vlimit_565.getParentScope+() = func
and vsession_id_564.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
