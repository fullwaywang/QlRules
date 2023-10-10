/**
 * @name linux-1816494330a83f2a064499d8ed2797045641f92c-chap_server_compute_md5
 * @id cpp/linux/1816494330a83f2a064499d8ed2797045641f92c/chap_server_compute_md5
 * @description linux-1816494330a83f2a064499d8ed2797045641f92c-chap_server_compute_md5 CVE-2018-14633
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Variable vclient_digest_191, Variable vchap_r_193) {
	exists(FunctionCall target_0 |
		target_0.getTarget().hasName("chap_string_to_hex")
		and not target_0.getTarget().hasName("printk")
		and target_0.getArgument(0).(VariableAccess).getTarget()=vclient_digest_191
		and target_0.getArgument(1).(VariableAccess).getTarget()=vchap_r_193
		and target_0.getArgument(2) instanceof FunctionCall)
}

predicate func_1(Variable vchallenge_189, Variable vchallenge_binhex_190) {
	exists(FunctionCall target_1 |
		target_1.getTarget().hasName("chap_string_to_hex")
		and not target_1.getTarget().hasName("hex2bin")
		and target_1.getArgument(0).(VariableAccess).getTarget()=vchallenge_binhex_190
		and target_1.getArgument(1).(VariableAccess).getTarget()=vchallenge_189
		and target_1.getArgument(2) instanceof FunctionCall)
}

predicate func_2(Function func) {
	exists(IfStmt target_2 |
		target_2.getCondition().(EqualityOperation).getAnOperand() instanceof FunctionCall
		and target_2.getCondition().(EqualityOperation).getAnOperand().(MulExpr).getValue()="32"
		and target_2.getCondition().(EqualityOperation).getAnOperand().(MulExpr).getLeftOperand().(Literal).getValue()="16"
		and target_2.getCondition().(EqualityOperation).getAnOperand().(MulExpr).getRightOperand().(Literal).getValue()="2"
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("printk")
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(StringLiteral).getValue()="3Malformed CHAP_R\n"
		and target_2.getThen().(BlockStmt).getStmt(1).(GotoStmt).toString() = "goto ..."
		and (func.getEntryPoint().(BlockStmt).getStmt(32)=target_2 or func.getEntryPoint().(BlockStmt).getStmt(32).getFollowingStmt()=target_2))
}

predicate func_5(Variable vclient_digest_191, Variable vchap_r_193, Function func) {
	exists(IfStmt target_5 |
		target_5.getCondition().(RelationalOperation).getLesserOperand().(FunctionCall).getTarget().hasName("hex2bin")
		and target_5.getCondition().(RelationalOperation).getLesserOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vclient_digest_191
		and target_5.getCondition().(RelationalOperation).getLesserOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vchap_r_193
		and target_5.getCondition().(RelationalOperation).getLesserOperand().(FunctionCall).getArgument(2).(Literal).getValue()="16"
		and target_5.getCondition().(RelationalOperation).getGreaterOperand().(Literal).getValue()="0"
		and target_5.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("printk")
		and target_5.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(StringLiteral).getValue()="3Malformed CHAP_R\n"
		and target_5.getThen().(BlockStmt).getStmt(1).(GotoStmt).toString() = "goto ..."
		and (func.getEntryPoint().(BlockStmt).getStmt(33)=target_5 or func.getEntryPoint().(BlockStmt).getStmt(33).getFollowingStmt()=target_5))
}

predicate func_9(Variable vchallenge_len_198) {
	exists(DivExpr target_9 |
		target_9.getLeftOperand().(SubExpr).getLeftOperand().(AddExpr).getAnOperand() instanceof FunctionCall
		and target_9.getLeftOperand().(SubExpr).getLeftOperand().(AddExpr).getAnOperand().(Literal).getValue()="2"
		and target_9.getLeftOperand().(SubExpr).getRightOperand().(Literal).getValue()="1"
		and target_9.getRightOperand().(Literal).getValue()="2"
		and target_9.getParent().(AssignExpr).getRValue() = target_9
		and target_9.getParent().(AssignExpr).getLValue().(VariableAccess).getTarget()=vchallenge_len_198)
}

predicate func_10(Variable vchallenge_189, Variable vchallenge_binhex_190, Variable vchallenge_len_198, Function func) {
	exists(IfStmt target_10 |
		target_10.getCondition().(RelationalOperation).getLesserOperand().(FunctionCall).getTarget().hasName("hex2bin")
		and target_10.getCondition().(RelationalOperation).getLesserOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vchallenge_binhex_190
		and target_10.getCondition().(RelationalOperation).getLesserOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vchallenge_189
		and target_10.getCondition().(RelationalOperation).getLesserOperand().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vchallenge_len_198
		and target_10.getCondition().(RelationalOperation).getGreaterOperand().(Literal).getValue()="0"
		and target_10.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("printk")
		and target_10.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(StringLiteral).getValue()="3Malformed CHAP_C\n"
		and target_10.getThen().(BlockStmt).getStmt(1).(GotoStmt).toString() = "goto ..."
		and (func.getEntryPoint().(BlockStmt).getStmt(63)=target_10 or func.getEntryPoint().(BlockStmt).getStmt(63).getFollowingStmt()=target_10))
}

predicate func_13(Variable vchap_r_193) {
	exists(FunctionCall target_13 |
		target_13.getTarget().hasName("strlen")
		and target_13.getArgument(0).(VariableAccess).getTarget()=vchap_r_193)
}

predicate func_14(Variable vchallenge_189) {
	exists(FunctionCall target_14 |
		target_14.getTarget().hasName("strlen")
		and target_14.getArgument(0).(VariableAccess).getTarget()=vchallenge_189)
}

predicate func_19(Variable vchallenge_len_198) {
	exists(AssignExpr target_19 |
		target_19.getLValue().(VariableAccess).getTarget()=vchallenge_len_198
		and target_19.getRValue() instanceof FunctionCall)
}

from Function func, Variable vchallenge_189, Variable vchallenge_binhex_190, Variable vclient_digest_191, Variable vchap_r_193, Variable vchallenge_len_198
where
func_0(vclient_digest_191, vchap_r_193)
and func_1(vchallenge_189, vchallenge_binhex_190)
and not func_2(func)
and not func_5(vclient_digest_191, vchap_r_193, func)
and not func_9(vchallenge_len_198)
and not func_10(vchallenge_189, vchallenge_binhex_190, vchallenge_len_198, func)
and func_13(vchap_r_193)
and func_14(vchallenge_189)
and vchallenge_189.getType().hasName("unsigned char *")
and vchallenge_binhex_190.getType().hasName("unsigned char *")
and vclient_digest_191.getType().hasName("unsigned char[16]")
and vchap_r_193.getType().hasName("unsigned char[64]")
and vchallenge_len_198.getType().hasName("int")
and func_19(vchallenge_len_198)
and vchallenge_189.getParentScope+() = func
and vchallenge_binhex_190.getParentScope+() = func
and vclient_digest_191.getParentScope+() = func
and vchap_r_193.getParentScope+() = func
and vchallenge_len_198.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
