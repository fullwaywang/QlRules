/**
 * @name php-bab0b99f376dac9170ac81382a5ed526938d595a-parse_ip_address_ex
 * @id cpp/php/bab0b99f376dac9170ac81382a5ed526938d595a/parse-ip-address-ex
 * @description php-bab0b99f376dac9170ac81382a5ed526938d595a-main/streams/xp_socket.c-parse_ip_address_ex CVE-2017-7272
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vp_574, VariableAccess target_0) {
		target_0.getTarget()=vp_574
		and target_0.getParent().(AssignExpr).getLValue() = target_0
		and target_0.getParent().(AssignExpr).getRValue() instanceof FunctionCall
}

predicate func_1(Variable vhost_571, VariableAccess target_1) {
		target_1.getTarget()=vhost_571
		and target_1.getParent().(AssignExpr).getLValue() = target_1
		and target_1.getParent().(AssignExpr).getRValue() instanceof FunctionCall
}

predicate func_2(Variable vhost_571, VariableAccess target_2) {
		target_2.getTarget()=vhost_571
}

predicate func_3(Function func) {
	exists(Initializer target_3 |
		target_3.getExpr() instanceof FunctionCall
		and target_3.getExpr().getEnclosingFunction() = func)
}

predicate func_5(Function func) {
	exists(FunctionCall target_5 |
		target_5.getTarget().hasName("strtol")
		and target_5.getArgument(0) instanceof PointerArithmeticOperation
		and target_5.getArgument(1).(AddressOfExpr).getOperand().(VariableAccess).getType().hasName("char *")
		and target_5.getArgument(2).(Literal).getValue()="10"
		and target_5.getParent().(AssignExpr).getRValue() = target_5
		and target_5.getParent().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget().getType().hasName("int *")
		and target_5.getEnclosingFunction() = func)
}

predicate func_6(LogicalAndExpr target_21, Function func) {
	exists(IfStmt target_6 |
		target_6.getCondition().(LogicalAndExpr).getAnOperand().(VariableAccess).getType().hasName("char *")
		and target_6.getCondition().(LogicalAndExpr).getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getType().hasName("char *")
		and target_6.getThen() instanceof BlockStmt
		and target_6.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(3)=target_6
		and target_6.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_21
		and target_6.getEnclosingFunction() = func)
}

predicate func_7(Function func) {
	exists(FunctionCall target_7 |
		target_7.getTarget().hasName("strtol")
		and target_7.getArgument(0) instanceof PointerArithmeticOperation
		and target_7.getArgument(1).(AddressOfExpr).getOperand().(VariableAccess).getType().hasName("char *")
		and target_7.getArgument(2).(Literal).getValue()="10"
		and target_7.getParent().(AssignExpr).getRValue() = target_7
		and target_7.getParent().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget().getType().hasName("int *")
		and target_7.getEnclosingFunction() = func)
}

predicate func_8(VariableAccess target_22, Function func) {
	exists(IfStmt target_8 |
		target_8.getCondition().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(VariableAccess).getType().hasName("char *")
		and target_8.getCondition().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getType().hasName("char *")
		and target_8.getThen().(BlockStmt).getStmt(0).(ReturnStmt).getExpr() instanceof FunctionCall
		and target_8.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(2)=target_8
		and target_8.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_22
		and target_8.getEnclosingFunction() = func)
}

predicate func_9(Parameter vstr_568, Parameter vget_err_568, Parameter verr_568, ExprStmt target_23, PointerArithmeticOperation target_24, IfStmt target_25, IfStmt target_26, ExprStmt target_27, Function func) {
	exists(IfStmt target_9 |
		target_9.getCondition().(VariableAccess).getTarget()=vget_err_568
		and target_9.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=verr_568
		and target_9.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("strpprintf")
		and target_9.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(Literal).getValue()="0"
		and target_9.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(StringLiteral).getValue()="Failed to parse address \"%s\""
		and target_9.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vstr_568
		and (func.getEntryPoint().(BlockStmt).getStmt(5)=target_9 or func.getEntryPoint().(BlockStmt).getStmt(5).getFollowingStmt()=target_9)
		and target_23.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getLocation().isBefore(target_9.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getLocation())
		and target_9.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getLocation().isBefore(target_24.getAnOperand().(VariableAccess).getLocation())
		and target_25.getCondition().(VariableAccess).getLocation().isBefore(target_9.getCondition().(VariableAccess).getLocation())
		and target_9.getCondition().(VariableAccess).getLocation().isBefore(target_26.getCondition().(VariableAccess).getLocation())
		and target_9.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getLocation().isBefore(target_27.getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getLocation()))
}

/*predicate func_10(Parameter vstr_568, Parameter verr_568, ExprStmt target_23, PointerArithmeticOperation target_24, ExprStmt target_27) {
	exists(AssignExpr target_10 |
		target_10.getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=verr_568
		and target_10.getRValue().(FunctionCall).getTarget().hasName("strpprintf")
		and target_10.getRValue().(FunctionCall).getArgument(0).(Literal).getValue()="0"
		and target_10.getRValue().(FunctionCall).getArgument(1).(StringLiteral).getValue()="Failed to parse address \"%s\""
		and target_10.getRValue().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vstr_568
		and target_23.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getLocation().isBefore(target_10.getRValue().(FunctionCall).getArgument(2).(VariableAccess).getLocation())
		and target_10.getRValue().(FunctionCall).getArgument(2).(VariableAccess).getLocation().isBefore(target_24.getAnOperand().(VariableAccess).getLocation())
		and target_10.getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getLocation().isBefore(target_27.getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getLocation()))
}

*/
predicate func_12(Parameter vstr_568, Parameter vstr_len_568, Variable vp_574, FunctionCall target_12) {
		target_12.getTarget().hasName("memchr")
		and target_12.getArgument(0).(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vstr_568
		and target_12.getArgument(0).(PointerArithmeticOperation).getAnOperand().(Literal).getValue()="1"
		and target_12.getArgument(1).(CharLiteral).getValue()="93"
		and target_12.getArgument(2).(SubExpr).getLeftOperand().(VariableAccess).getTarget()=vstr_len_568
		and target_12.getArgument(2).(SubExpr).getRightOperand().(Literal).getValue()="2"
		and target_12.getParent().(AssignExpr).getRValue() = target_12
		and target_12.getParent().(AssignExpr).getLValue().(VariableAccess).getTarget()=vp_574
}

predicate func_13(Variable vp_574, PointerArithmeticOperation target_13) {
		target_13.getAnOperand().(VariableAccess).getTarget()=vp_574
		and target_13.getAnOperand().(Literal).getValue()="2"
		and target_13.getParent().(FunctionCall).getParent().(AssignExpr).getRValue() instanceof FunctionCall
}

predicate func_14(Variable vcolon_570, PointerArithmeticOperation target_14) {
		target_14.getAnOperand().(VariableAccess).getTarget()=vcolon_570
		and target_14.getAnOperand().(Literal).getValue()="1"
		and target_14.getParent().(FunctionCall).getParent().(AssignExpr).getRValue() instanceof FunctionCall
}

predicate func_15(Parameter vstr_568, Variable vcolon_570, Variable vhost_571, FunctionCall target_15) {
		target_15.getTarget().hasName("_estrndup")
		and target_15.getArgument(0).(VariableAccess).getTarget()=vstr_568
		and target_15.getArgument(1).(PointerArithmeticOperation).getLeftOperand().(VariableAccess).getTarget()=vcolon_570
		and target_15.getArgument(1).(PointerArithmeticOperation).getRightOperand().(VariableAccess).getTarget()=vstr_568
		and target_15.getParent().(AssignExpr).getRValue() = target_15
		and target_15.getParent().(AssignExpr).getLValue().(VariableAccess).getTarget()=vhost_571
}

predicate func_16(Parameter vstr_568, Parameter vget_err_568, Parameter verr_568, VariableAccess target_22, BlockStmt target_16) {
		target_16.getStmt(0).(IfStmt).getCondition().(VariableAccess).getTarget()=vget_err_568
		and target_16.getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=verr_568
		and target_16.getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("strpprintf")
		and target_16.getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(Literal).getValue()="0"
		and target_16.getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(StringLiteral).getValue()="Failed to parse address \"%s\""
		and target_16.getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vstr_568
		and target_16.getStmt(1).(ReturnStmt).getExpr().(Literal).getValue()="0"
		and target_16.getParent().(IfStmt).getCondition()=target_22
}

predicate func_17(Variable vp_574, AssignExpr target_17) {
		target_17.getLValue().(VariableAccess).getTarget()=vp_574
		and target_17.getRValue() instanceof FunctionCall
}

predicate func_18(Function func, FunctionCall target_18) {
		target_18.getTarget().hasName("atoi")
		and target_18.getArgument(0) instanceof PointerArithmeticOperation
		and target_18.getParent().(AssignExpr).getRValue() = target_18
		and target_18.getParent().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget().getType().hasName("int *")
		and target_18.getEnclosingFunction() = func
}

predicate func_19(Function func, FunctionCall target_19) {
		target_19.getTarget().hasName("atoi")
		and target_19.getArgument(0) instanceof PointerArithmeticOperation
		and target_19.getParent().(AssignExpr).getRValue() = target_19
		and target_19.getParent().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget().getType().hasName("int *")
		and target_19.getEnclosingFunction() = func
}

predicate func_20(Variable vhost_571, VariableAccess target_22, ExprStmt target_20) {
		target_20.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vhost_571
		and target_20.getExpr().(AssignExpr).getRValue() instanceof FunctionCall
		and target_20.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_22
}

predicate func_21(Parameter vstr_568, Parameter vstr_len_568, LogicalAndExpr target_21) {
		target_21.getAnOperand().(EqualityOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vstr_568
		and target_21.getAnOperand().(EqualityOperation).getAnOperand().(CharLiteral).getValue()="91"
		and target_21.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vstr_len_568
		and target_21.getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="1"
}

predicate func_22(Variable vcolon_570, VariableAccess target_22) {
		target_22.getTarget()=vcolon_570
}

predicate func_23(Parameter vstr_568, Parameter verr_568, ExprStmt target_23) {
		target_23.getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=verr_568
		and target_23.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("strpprintf")
		and target_23.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(Literal).getValue()="0"
		and target_23.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(StringLiteral).getValue()="Failed to parse IPv6 address \"%s\""
		and target_23.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vstr_568
}

predicate func_24(Parameter vstr_568, PointerArithmeticOperation target_24) {
		target_24.getAnOperand().(VariableAccess).getTarget()=vstr_568
		and target_24.getAnOperand().(Literal).getValue()="1"
}

predicate func_25(Parameter vstr_568, Parameter vget_err_568, Parameter verr_568, IfStmt target_25) {
		target_25.getCondition().(VariableAccess).getTarget()=vget_err_568
		and target_25.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=verr_568
		and target_25.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("strpprintf")
		and target_25.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(Literal).getValue()="0"
		and target_25.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(StringLiteral).getValue()="Failed to parse IPv6 address \"%s\""
		and target_25.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vstr_568
}

predicate func_26(Parameter vstr_568, Parameter vget_err_568, Parameter verr_568, IfStmt target_26) {
		target_26.getCondition().(VariableAccess).getTarget()=vget_err_568
		and target_26.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=verr_568
		and target_26.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("strpprintf")
		and target_26.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(Literal).getValue()="0"
		and target_26.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(StringLiteral).getValue()="Failed to parse address \"%s\""
		and target_26.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vstr_568
}

predicate func_27(Parameter vstr_568, Parameter verr_568, ExprStmt target_27) {
		target_27.getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=verr_568
		and target_27.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("strpprintf")
		and target_27.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(Literal).getValue()="0"
		and target_27.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(StringLiteral).getValue()="Failed to parse address \"%s\""
		and target_27.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vstr_568
}

from Function func, Parameter vstr_568, Parameter vstr_len_568, Parameter vget_err_568, Parameter verr_568, Variable vcolon_570, Variable vhost_571, Variable vp_574, VariableAccess target_0, VariableAccess target_1, VariableAccess target_2, FunctionCall target_12, PointerArithmeticOperation target_13, PointerArithmeticOperation target_14, FunctionCall target_15, BlockStmt target_16, AssignExpr target_17, FunctionCall target_18, FunctionCall target_19, ExprStmt target_20, LogicalAndExpr target_21, VariableAccess target_22, ExprStmt target_23, PointerArithmeticOperation target_24, IfStmt target_25, IfStmt target_26, ExprStmt target_27
where
func_0(vp_574, target_0)
and func_1(vhost_571, target_1)
and func_2(vhost_571, target_2)
and not func_3(func)
and not func_5(func)
and not func_6(target_21, func)
and not func_7(func)
and not func_8(target_22, func)
and not func_9(vstr_568, vget_err_568, verr_568, target_23, target_24, target_25, target_26, target_27, func)
and func_12(vstr_568, vstr_len_568, vp_574, target_12)
and func_13(vp_574, target_13)
and func_14(vcolon_570, target_14)
and func_15(vstr_568, vcolon_570, vhost_571, target_15)
and func_16(vstr_568, vget_err_568, verr_568, target_22, target_16)
and func_17(vp_574, target_17)
and func_18(func, target_18)
and func_19(func, target_19)
and func_20(vhost_571, target_22, target_20)
and func_21(vstr_568, vstr_len_568, target_21)
and func_22(vcolon_570, target_22)
and func_23(vstr_568, verr_568, target_23)
and func_24(vstr_568, target_24)
and func_25(vstr_568, vget_err_568, verr_568, target_25)
and func_26(vstr_568, vget_err_568, verr_568, target_26)
and func_27(vstr_568, verr_568, target_27)
and vstr_568.getType().hasName("const char *")
and vstr_len_568.getType().hasName("size_t")
and vget_err_568.getType().hasName("int")
and verr_568.getType().hasName("zend_string **")
and vcolon_570.getType().hasName("char *")
and vhost_571.getType().hasName("char *")
and vp_574.getType().hasName("char *")
and vstr_568.getFunction() = func
and vstr_len_568.getFunction() = func
and vget_err_568.getFunction() = func
and verr_568.getFunction() = func
and vcolon_570.(LocalVariable).getFunction() = func
and vhost_571.(LocalVariable).getFunction() = func
and vp_574.(LocalVariable).getFunction() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
