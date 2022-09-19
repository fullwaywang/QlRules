import cpp

predicate func_0(Function func) {
	exists(Literal target_0 |
		target_0.getValue()="301"
		and not target_0.getValue()="362"
		and target_0.getEnclosingFunction() = func)
}

predicate func_1(Function func) {
	exists(VariableAccess target_1 |
		target_1.getParent().(NEExpr).getRightOperand().(Literal).getValue()="0"
		and target_1.getParent().(NEExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0) instanceof IfStmt
		and target_1.getEnclosingFunction() = func)
}

predicate func_2(Function func) {
	exists(FunctionCall target_2 |
		target_2.getTarget().hasName("BN_set_word")
		and not target_2.getTarget().hasName("BN_num_bits")
		and target_2.getType().hasName("int")
		and target_2.getArgument(0) instanceof AddressOfExpr
		and target_2.getArgument(1) instanceof Literal
		and target_2.getEnclosingFunction() = func)
}

predicate func_9(Parameter vcofactor, Function func) {
	exists(IfStmt target_9 |
		target_9.getCondition().(LogicalAndExpr).getType().hasName("int")
		and target_9.getCondition().(LogicalAndExpr).getLeftOperand().(NEExpr).getType().hasName("int")
		and target_9.getCondition().(LogicalAndExpr).getLeftOperand().(NEExpr).getLeftOperand().(VariableAccess).getTarget()=vcofactor
		and target_9.getCondition().(LogicalAndExpr).getLeftOperand().(NEExpr).getRightOperand().(Literal).getValue()="0"
		and target_9.getCondition().(LogicalAndExpr).getRightOperand().(NEExpr).getType().hasName("int")
		and target_9.getCondition().(LogicalAndExpr).getRightOperand().(NEExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="neg"
		and target_9.getCondition().(LogicalAndExpr).getRightOperand().(NEExpr).getLeftOperand().(PointerFieldAccess).getType().hasName("int")
		and target_9.getCondition().(LogicalAndExpr).getRightOperand().(NEExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcofactor
		and target_9.getCondition().(LogicalAndExpr).getRightOperand().(NEExpr).getRightOperand().(Literal).getValue()="0"
		and target_9.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ERR_put_error")
		and target_9.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getType().hasName("void")
		and target_9.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(Literal).getValue()="16"
		and target_9.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="111"
		and target_9.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(Literal).getValue()="152"
		and target_9.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(StringLiteral).getValue()="ec_lib.c"
		and target_9.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(4).(Literal).getValue()="389"
		and target_9.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(Literal).getValue()="0"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_9)
}

predicate func_10(Parameter vgroup, Parameter vcofactor, Function func) {
	exists(IfStmt target_10 |
		target_10.getCondition().(LogicalAndExpr).getType().hasName("int")
		and target_10.getCondition().(LogicalAndExpr).getLeftOperand().(NEExpr).getType().hasName("int")
		and target_10.getCondition().(LogicalAndExpr).getLeftOperand().(NEExpr).getLeftOperand().(VariableAccess).getTarget()=vcofactor
		and target_10.getCondition().(LogicalAndExpr).getLeftOperand().(NEExpr).getRightOperand().(Literal).getValue()="0"
		and target_10.getCondition().(LogicalAndExpr).getRightOperand().(NotExpr).getType().hasName("int")
		and target_10.getCondition().(LogicalAndExpr).getRightOperand().(NotExpr).getOperand().(EQExpr).getType().hasName("int")
		and target_10.getCondition().(LogicalAndExpr).getRightOperand().(NotExpr).getOperand().(EQExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="top"
		and target_10.getCondition().(LogicalAndExpr).getRightOperand().(NotExpr).getOperand().(EQExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcofactor
		and target_10.getCondition().(LogicalAndExpr).getRightOperand().(NotExpr).getOperand().(EQExpr).getRightOperand().(Literal).getValue()="0"
		and target_10.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(NotExpr).getType().hasName("int")
		and target_10.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("BN_copy")
		and target_10.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="cofactor"
		and target_10.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vgroup
		and target_10.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vcofactor
		and target_10.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(ReturnStmt).getExpr().(Literal).getValue()="0"
		and target_10.getElse().(IfStmt).getCondition().(NotExpr).getType().hasName("int")
		and target_10.getElse().(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("ec_guess_cofactor")
		and target_10.getElse().(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getType().hasName("int")
		and target_10.getElse().(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vgroup
		and target_10.getElse().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("BN_set_word")
		and target_10.getElse().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="cofactor"
		and target_10.getElse().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vgroup
		and target_10.getElse().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="0"
		and target_10.getElse().(IfStmt).getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(Literal).getValue()="0"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_10)
}

predicate func_11(Parameter vgroup, Parameter vorder) {
	exists(IfStmt target_11 |
		target_11.getCondition().(NotExpr).getType().hasName("int")
		and target_11.getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("BN_copy")
		and target_11.getCondition().(NotExpr).getOperand().(FunctionCall).getType().hasName("BIGNUM *")
		and target_11.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(AddressOfExpr).getType().hasName("BIGNUM *")
		and target_11.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="order"
		and target_11.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vgroup
		and target_11.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vorder
		and target_11.getThen().(ReturnStmt).getExpr().(Literal).getValue()="0"
		and target_11.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(NEExpr).getType().hasName("int")
		and target_11.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(NEExpr).getLeftOperand().(VariableAccess).getTarget()=vorder
		and target_11.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(NEExpr).getRightOperand().(Literal).getValue()="0")
}

predicate func_12(Parameter vgroup) {
	exists(AddressOfExpr target_12 |
		target_12.getType().hasName("BIGNUM *")
		and target_12.getOperand().(PointerFieldAccess).getTarget().getName()="order"
		and target_12.getOperand().(PointerFieldAccess).getType().hasName("BIGNUM")
		and target_12.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vgroup)
}

predicate func_14(Parameter vgroup, Parameter vcofactor) {
	exists(ExprStmt target_14 |
		target_14.getExpr().(FunctionCall).getTarget().hasName("BN_set_word")
		and target_14.getExpr().(FunctionCall).getType().hasName("int")
		and target_14.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getType().hasName("BIGNUM *")
		and target_14.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="cofactor"
		and target_14.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getType().hasName("BIGNUM")
		and target_14.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vgroup
		and target_14.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="0"
		and target_14.getParent().(IfStmt).getCondition().(NEExpr).getType().hasName("int")
		and target_14.getParent().(IfStmt).getCondition().(NEExpr).getLeftOperand().(VariableAccess).getTarget()=vcofactor
		and target_14.getParent().(IfStmt).getCondition().(NEExpr).getRightOperand().(Literal).getValue()="0")
}

predicate func_15(Function func) {
	exists(Literal target_15 |
		target_15.getValue()="0"
		and target_15.getEnclosingFunction() = func)
}

from Function func, Parameter vgroup, Parameter vorder, Parameter vcofactor
where
func_0(func)
and func_1(func)
and func_2(func)
and not func_9(vcofactor, func)
and not func_10(vgroup, vcofactor, func)
and func_11(vgroup, vorder)
and func_12(vgroup)
and func_14(vgroup, vcofactor)
and func_15(func)
and vgroup.getType().hasName("EC_GROUP *")
and vorder.getType().hasName("const BIGNUM *")
and vcofactor.getType().hasName("const BIGNUM *")
and vgroup.getParentScope+() = func
and vorder.getParentScope+() = func
and vcofactor.getParentScope+() = func
select func, vgroup, vorder, vcofactor
