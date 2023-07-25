/**
 * @name libssh2-dc109a7f518757741590bb993c0c8412928ccec2-userauth_hostbased_fromfile
 * @id cpp/libssh2/dc109a7f518757741590bb993c0c8412928ccec2/userauth-hostbased-fromfile
 * @description libssh2-dc109a7f518757741590bb993c0c8412928ccec2-src/userauth.c-userauth_hostbased_fromfile CVE-2019-3859
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vrc_794, Variable vdata_len_980, BlockStmt target_2, EqualityOperation target_3, AddressOfExpr target_4) {
	exists(LogicalOrExpr target_0 |
		target_0.getAnOperand().(VariableAccess).getTarget()=vrc_794
		and target_0.getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vdata_len_980
		and target_0.getAnOperand().(RelationalOperation).getGreaterOperand().(Literal).getValue()="1"
		and target_0.getParent().(IfStmt).getThen()=target_2
		and target_3.getAnOperand().(VariableAccess).getLocation().isBefore(target_0.getAnOperand().(VariableAccess).getLocation())
		and target_4.getOperand().(VariableAccess).getLocation().isBefore(target_0.getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getLocation()))
}

predicate func_1(Variable vrc_794, BlockStmt target_2, VariableAccess target_1) {
		target_1.getTarget()=vrc_794
		and target_1.getParent().(IfStmt).getThen()=target_2
}

predicate func_2(BlockStmt target_2) {
		target_2.getStmt(0).(ReturnStmt).getExpr().(FunctionCall).getTarget().hasName("_libssh2_error")
		and target_2.getStmt(0).(ReturnStmt).getExpr().(FunctionCall).getArgument(1).(UnaryMinusExpr).getValue()="-19"
		and target_2.getStmt(0).(ReturnStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="Auth failed"
}

predicate func_3(Variable vrc_794, EqualityOperation target_3) {
		target_3.getAnOperand().(VariableAccess).getTarget()=vrc_794
		and target_3.getAnOperand().(UnaryMinusExpr).getValue()="-37"
}

predicate func_4(Variable vdata_len_980, AddressOfExpr target_4) {
		target_4.getOperand().(VariableAccess).getTarget()=vdata_len_980
}

from Function func, Variable vrc_794, Variable vdata_len_980, VariableAccess target_1, BlockStmt target_2, EqualityOperation target_3, AddressOfExpr target_4
where
not func_0(vrc_794, vdata_len_980, target_2, target_3, target_4)
and func_1(vrc_794, target_2, target_1)
and func_2(target_2)
and func_3(vrc_794, target_3)
and func_4(vdata_len_980, target_4)
and vrc_794.getType().hasName("int")
and vdata_len_980.getType().hasName("size_t")
and vrc_794.getParentScope+() = func
and vdata_len_980.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
