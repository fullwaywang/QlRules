/**
 * @name libssh2-f15b1e297f72882214988101ccdc5e6ad30d7e6e-sftp_init
 * @id cpp/libssh2/f15b1e297f72882214988101ccdc5e6ad30d7e6e/sftp-init
 * @description libssh2-f15b1e297f72882214988101ccdc5e6ad30d7e6e-src/sftp.c-sftp_init CVE-2019-3862
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vsession_708, RelationalOperation target_11, ExprStmt target_12, ExprStmt target_3) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(FunctionCall).getTarget().hasName("_libssh2_error")
		and target_0.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsession_708
		and target_0.getExpr().(FunctionCall).getArgument(1).(UnaryMinusExpr).getValue()="-37"
		and target_0.getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="Would block receiving SSH_FXP_VERSION"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0)=target_0
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_11
		and target_12.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_0.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_0.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_3.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

predicate func_1(Variable vdata_len_711, Variable vrc_712, EqualityOperation target_13, AddressOfExpr target_14, RelationalOperation target_15, IfStmt target_7) {
	exists(IfStmt target_1 |
		target_1.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vrc_712
		and target_1.getCondition().(EqualityOperation).getAnOperand().(UnaryMinusExpr).getValue()="-41"
		and target_1.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vdata_len_711
		and target_1.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(Literal).getValue()="0"
		and target_1.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0) instanceof ExprStmt
		and target_1.getThen().(BlockStmt).getStmt(1) instanceof ExprStmt
		and target_1.getThen().(BlockStmt).getStmt(2) instanceof GotoStmt
		and target_1.getElse() instanceof IfStmt
		and target_1.getParent().(IfStmt).getCondition()=target_13
		and target_14.getOperand().(VariableAccess).getLocation().isBefore(target_1.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation())
		and target_1.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation().isBefore(target_15.getGreaterOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getLocation())
		and target_1.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getLocation().isBefore(target_7.getCondition().(VariableAccess).getLocation()))
}

/*predicate func_2(Variable vdata_len_711, BlockStmt target_16, AddressOfExpr target_14, RelationalOperation target_15) {
	exists(RelationalOperation target_2 |
		 (target_2 instanceof GTExpr or target_2 instanceof LTExpr)
		and target_2.getGreaterOperand().(VariableAccess).getTarget()=vdata_len_711
		and target_2.getLesserOperand().(Literal).getValue()="0"
		and target_2.getParent().(IfStmt).getThen()=target_16
		and target_14.getOperand().(VariableAccess).getLocation().isBefore(target_2.getGreaterOperand().(VariableAccess).getLocation())
		and target_2.getGreaterOperand().(VariableAccess).getLocation().isBefore(target_15.getGreaterOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getLocation()))
}

*/
predicate func_3(Parameter vsession_708, RelationalOperation target_11, ExprStmt target_3) {
		target_3.getExpr().(FunctionCall).getTarget().hasName("_libssh2_error")
		and target_3.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsession_708
		and target_3.getExpr().(FunctionCall).getArgument(1).(UnaryMinusExpr).getValue()="-31"
		and target_3.getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="Invalid SSH_FXP_VERSION response"
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_11
}

predicate func_4(Variable vdata_710, Parameter vsession_708, RelationalOperation target_11, ExprStmt target_4) {
		target_4.getExpr().(VariableCall).getExpr().(PointerFieldAccess).getTarget().getName()="free"
		and target_4.getExpr().(VariableCall).getExpr().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsession_708
		and target_4.getExpr().(VariableCall).getArgument(0).(VariableAccess).getTarget()=vdata_710
		and target_4.getExpr().(VariableCall).getArgument(1).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="abstract"
		and target_4.getExpr().(VariableCall).getArgument(1).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsession_708
		and target_4.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_11
}

predicate func_5(Function func, ReturnStmt target_5) {
		target_5.getExpr().(Literal).getValue()="0"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_5
}

predicate func_6(EqualityOperation target_13, Function func, ReturnStmt target_6) {
		target_6.getExpr().(Literal).getValue()="0"
		and target_6.getParent().(IfStmt).getCondition()=target_13
		and target_6.getEnclosingFunction() = func
}

predicate func_7(Variable vrc_712, Parameter vsession_708, EqualityOperation target_13, IfStmt target_7) {
		target_7.getCondition().(VariableAccess).getTarget()=vrc_712
		and target_7.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("_libssh2_error")
		and target_7.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsession_708
		and target_7.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vrc_712
		and target_7.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="Timeout waiting for response from SFTP subsystem"
		and target_7.getThen().(BlockStmt).getStmt(1).(GotoStmt).toString() = "goto ..."
		and target_7.getThen().(BlockStmt).getStmt(1).(GotoStmt).getName() ="sftp_init_error"
		and target_7.getParent().(IfStmt).getCondition()=target_13
}

predicate func_8(RelationalOperation target_11, Function func, GotoStmt target_8) {
		target_8.toString() = "goto ..."
		and target_8.getName() ="sftp_init_error"
		and target_8.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_11
		and target_8.getEnclosingFunction() = func
}

predicate func_9(Variable vdata_len_711, BlockStmt target_16, VariableAccess target_9) {
		target_9.getTarget()=vdata_len_711
		and target_9.getParent().(LTExpr).getGreaterOperand().(Literal).getValue()="5"
		and target_9.getParent().(LTExpr).getParent().(IfStmt).getThen()=target_16
}

predicate func_11(Variable vdata_len_711, BlockStmt target_16, RelationalOperation target_11) {
		 (target_11 instanceof GTExpr or target_11 instanceof LTExpr)
		and target_11.getLesserOperand().(VariableAccess).getTarget()=vdata_len_711
		and target_11.getGreaterOperand() instanceof Literal
		and target_11.getParent().(IfStmt).getThen()=target_16
}

predicate func_12(Variable vrc_712, Parameter vsession_708, ExprStmt target_12) {
		target_12.getExpr().(FunctionCall).getTarget().hasName("_libssh2_error")
		and target_12.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsession_708
		and target_12.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vrc_712
		and target_12.getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="Timeout waiting for response from SFTP subsystem"
}

predicate func_13(Variable vrc_712, EqualityOperation target_13) {
		target_13.getAnOperand().(VariableAccess).getTarget()=vrc_712
		and target_13.getAnOperand().(UnaryMinusExpr).getValue()="-37"
}

predicate func_14(Variable vdata_len_711, AddressOfExpr target_14) {
		target_14.getOperand().(VariableAccess).getTarget()=vdata_len_711
}

predicate func_15(Variable vdata_710, Variable vdata_len_711, RelationalOperation target_15) {
		 (target_15 instanceof GTExpr or target_15 instanceof LTExpr)
		and target_15.getGreaterOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vdata_710
		and target_15.getGreaterOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vdata_len_711
}

predicate func_16(BlockStmt target_16) {
		target_16.getStmt(0) instanceof ExprStmt
		and target_16.getStmt(1) instanceof ExprStmt
		and target_16.getStmt(2) instanceof GotoStmt
}

from Function func, Variable vdata_710, Variable vdata_len_711, Variable vrc_712, Parameter vsession_708, ExprStmt target_3, ExprStmt target_4, ReturnStmt target_5, ReturnStmt target_6, IfStmt target_7, GotoStmt target_8, VariableAccess target_9, RelationalOperation target_11, ExprStmt target_12, EqualityOperation target_13, AddressOfExpr target_14, RelationalOperation target_15, BlockStmt target_16
where
not func_0(vsession_708, target_11, target_12, target_3)
and not func_1(vdata_len_711, vrc_712, target_13, target_14, target_15, target_7)
and func_3(vsession_708, target_11, target_3)
and func_4(vdata_710, vsession_708, target_11, target_4)
and func_5(func, target_5)
and func_6(target_13, func, target_6)
and func_7(vrc_712, vsession_708, target_13, target_7)
and func_8(target_11, func, target_8)
and func_9(vdata_len_711, target_16, target_9)
and func_11(vdata_len_711, target_16, target_11)
and func_12(vrc_712, vsession_708, target_12)
and func_13(vrc_712, target_13)
and func_14(vdata_len_711, target_14)
and func_15(vdata_710, vdata_len_711, target_15)
and func_16(target_16)
and vdata_710.getType().hasName("unsigned char *")
and vdata_len_711.getType().hasName("size_t")
and vrc_712.getType().hasName("ssize_t")
and vsession_708.getType().hasName("LIBSSH2_SESSION *")
and vdata_710.getParentScope+() = func
and vdata_len_711.getParentScope+() = func
and vrc_712.getParentScope+() = func
and vsession_708.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
