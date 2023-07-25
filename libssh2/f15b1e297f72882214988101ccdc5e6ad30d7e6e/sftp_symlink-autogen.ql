/**
 * @name libssh2-f15b1e297f72882214988101ccdc5e6ad30d7e6e-sftp_symlink
 * @id cpp/libssh2/f15b1e297f72882214988101ccdc5e6ad30d7e6e/sftp-symlink
 * @description libssh2-f15b1e297f72882214988101ccdc5e6ad30d7e6e-src/sftp.c-sftp_symlink CVE-2019-3862
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_1(Variable vsession_3306, Variable vdata_len_3307, Variable vdata_3312, Variable vretcode_3315, EqualityOperation target_4, FunctionCall target_5, AddressOfExpr target_6, AddressOfExpr target_7, EqualityOperation target_8, ReturnStmt target_9, IfStmt target_3) {
	exists(IfStmt target_1 |
		target_1.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vretcode_3315
		and target_1.getCondition().(EqualityOperation).getAnOperand().(UnaryMinusExpr).getValue()="-41"
		and target_1.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vdata_len_3307
		and target_1.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(Literal).getValue()="0"
		and target_1.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(VariableCall).getExpr().(PointerFieldAccess).getTarget().getName()="free"
		and target_1.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(VariableCall).getArgument(0).(VariableAccess).getTarget()=vdata_3312
		and target_1.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(FunctionCall).getTarget().hasName("_libssh2_error")
		and target_1.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsession_3306
		and target_1.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(FunctionCall).getArgument(1).(UnaryMinusExpr).getValue()="-31"
		and target_1.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="SFTP symlink packet too short"
		and target_1.getElse() instanceof IfStmt
		and target_1.getParent().(IfStmt).getCondition()=target_4
		and target_1.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_5.getArgument(0).(VariableAccess).getLocation())
		and target_6.getOperand().(VariableAccess).getLocation().isBefore(target_1.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation())
		and target_7.getOperand().(VariableAccess).getLocation().isBefore(target_1.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(VariableCall).getArgument(0).(VariableAccess).getLocation())
		and target_1.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(VariableCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_8.getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getLocation())
		and target_9.getExpr().(VariableAccess).getLocation().isBefore(target_1.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getLocation())
		and target_1.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getLocation().isBefore(target_3.getCondition().(VariableAccess).getLocation()))
}

predicate func_2(Variable vsession_3306, Variable vdata_len_3307, Variable vdata_3312, ExprStmt target_10, ExprStmt target_11, PointerArithmeticOperation target_12, Function func) {
	exists(IfStmt target_2 |
		target_2.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vdata_len_3307
		and target_2.getCondition().(RelationalOperation).getGreaterOperand().(Literal).getValue()="13"
		and target_2.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vdata_len_3307
		and target_2.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(Literal).getValue()="0"
		and target_2.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(VariableCall).getExpr().(PointerFieldAccess).getTarget().getName()="free"
		and target_2.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(VariableCall).getArgument(0).(VariableAccess).getTarget()=vdata_3312
		and target_2.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(FunctionCall).getTarget().hasName("_libssh2_error")
		and target_2.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsession_3306
		and target_2.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(FunctionCall).getArgument(1).(UnaryMinusExpr).getValue()="-31"
		and target_2.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="SFTP stat packet too short"
		and (func.getEntryPoint().(BlockStmt).getStmt(15)=target_2 or func.getEntryPoint().(BlockStmt).getStmt(15).getFollowingStmt()=target_2)
		and target_2.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_10.getExpr().(VariableCall).getExpr().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_11.getExpr().(VariableCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_2.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(VariableCall).getArgument(0).(VariableAccess).getLocation())
		and target_2.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(VariableCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_12.getAnOperand().(VariableAccess).getLocation()))
}

predicate func_3(Parameter vsftp_3301, Variable vsession_3306, Variable vretcode_3315, EqualityOperation target_4, IfStmt target_3) {
		target_3.getCondition().(VariableAccess).getTarget()=vretcode_3315
		and target_3.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="symlink_state"
		and target_3.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsftp_3301
		and target_3.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(FunctionCall).getTarget().hasName("_libssh2_error")
		and target_3.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsession_3306
		and target_3.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vretcode_3315
		and target_3.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="Error waiting for status message"
		and target_3.getParent().(IfStmt).getCondition()=target_4
}

predicate func_4(Variable vretcode_3315, EqualityOperation target_4) {
		target_4.getAnOperand().(VariableAccess).getTarget()=vretcode_3315
		and target_4.getAnOperand().(UnaryMinusExpr).getValue()="-37"
}

predicate func_5(Variable vsession_3306, Variable vretcode_3315, FunctionCall target_5) {
		target_5.getTarget().hasName("_libssh2_error")
		and target_5.getArgument(0).(VariableAccess).getTarget()=vsession_3306
		and target_5.getArgument(1).(VariableAccess).getTarget()=vretcode_3315
		and target_5.getArgument(2).(StringLiteral).getValue()="Error waiting for status message"
}

predicate func_6(Variable vdata_len_3307, AddressOfExpr target_6) {
		target_6.getOperand().(VariableAccess).getTarget()=vdata_len_3307
}

predicate func_7(Variable vdata_3312, AddressOfExpr target_7) {
		target_7.getOperand().(VariableAccess).getTarget()=vdata_3312
}

predicate func_8(Variable vdata_3312, EqualityOperation target_8) {
		target_8.getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vdata_3312
		and target_8.getAnOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_8.getAnOperand().(Literal).getValue()="101"
}

predicate func_9(Variable vretcode_3315, ReturnStmt target_9) {
		target_9.getExpr().(VariableAccess).getTarget()=vretcode_3315
}

predicate func_10(Variable vsession_3306, Variable vdata_3312, ExprStmt target_10) {
		target_10.getExpr().(VariableCall).getExpr().(PointerFieldAccess).getTarget().getName()="free"
		and target_10.getExpr().(VariableCall).getExpr().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsession_3306
		and target_10.getExpr().(VariableCall).getArgument(0).(VariableAccess).getTarget()=vdata_3312
		and target_10.getExpr().(VariableCall).getArgument(1).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="abstract"
		and target_10.getExpr().(VariableCall).getArgument(1).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsession_3306
}

predicate func_11(Variable vsession_3306, Variable vdata_3312, ExprStmt target_11) {
		target_11.getExpr().(VariableCall).getExpr().(PointerFieldAccess).getTarget().getName()="free"
		and target_11.getExpr().(VariableCall).getExpr().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsession_3306
		and target_11.getExpr().(VariableCall).getArgument(0).(VariableAccess).getTarget()=vdata_3312
		and target_11.getExpr().(VariableCall).getArgument(1).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="abstract"
		and target_11.getExpr().(VariableCall).getArgument(1).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsession_3306
}

predicate func_12(Variable vdata_3312, PointerArithmeticOperation target_12) {
		target_12.getAnOperand().(VariableAccess).getTarget()=vdata_3312
		and target_12.getAnOperand().(Literal).getValue()="9"
}

from Function func, Parameter vsftp_3301, Variable vsession_3306, Variable vdata_len_3307, Variable vdata_3312, Variable vretcode_3315, IfStmt target_3, EqualityOperation target_4, FunctionCall target_5, AddressOfExpr target_6, AddressOfExpr target_7, EqualityOperation target_8, ReturnStmt target_9, ExprStmt target_10, ExprStmt target_11, PointerArithmeticOperation target_12
where
not func_1(vsession_3306, vdata_len_3307, vdata_3312, vretcode_3315, target_4, target_5, target_6, target_7, target_8, target_9, target_3)
and not func_2(vsession_3306, vdata_len_3307, vdata_3312, target_10, target_11, target_12, func)
and func_3(vsftp_3301, vsession_3306, vretcode_3315, target_4, target_3)
and func_4(vretcode_3315, target_4)
and func_5(vsession_3306, vretcode_3315, target_5)
and func_6(vdata_len_3307, target_6)
and func_7(vdata_3312, target_7)
and func_8(vdata_3312, target_8)
and func_9(vretcode_3315, target_9)
and func_10(vsession_3306, vdata_3312, target_10)
and func_11(vsession_3306, vdata_3312, target_11)
and func_12(vdata_3312, target_12)
and vsftp_3301.getType().hasName("LIBSSH2_SFTP *")
and vsession_3306.getType().hasName("LIBSSH2_SESSION *")
and vdata_len_3307.getType().hasName("size_t")
and vdata_3312.getType().hasName("unsigned char *")
and vretcode_3315.getType().hasName("int")
and vsftp_3301.getParentScope+() = func
and vsession_3306.getParentScope+() = func
and vdata_len_3307.getParentScope+() = func
and vdata_3312.getParentScope+() = func
and vretcode_3315.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
