import cpp

predicate func_0(Function func) {
	exists(Literal target_0 |
		target_0.getValue()="272"
		and not target_0.getValue()="333"
		and target_0.getEnclosingFunction() = func)
}

predicate func_2(Function func) {
	exists(FunctionCall target_2 |
		target_2.getTarget().hasName("BN_set_word")
		and not target_2.getTarget().hasName("BN_is_zero")
		and target_2.getType().hasName("int")
		and target_2.getArgument(0) instanceof PointerFieldAccess
		and target_2.getArgument(1) instanceof Literal
		and target_2.getEnclosingFunction() = func)
}

predicate func_3(Parameter vgroup) {
	exists(LogicalOrExpr target_3 |
		target_3.getType().hasName("int")
		and target_3.getLeftOperand().(LogicalOrExpr).getType().hasName("int")
		and target_3.getLeftOperand().(LogicalOrExpr).getLeftOperand().(EQExpr).getType().hasName("int")
		and target_3.getLeftOperand().(LogicalOrExpr).getLeftOperand().(EQExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="field"
		and target_3.getLeftOperand().(LogicalOrExpr).getLeftOperand().(EQExpr).getLeftOperand().(PointerFieldAccess).getType().hasName("BIGNUM *")
		and target_3.getLeftOperand().(LogicalOrExpr).getLeftOperand().(EQExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vgroup
		and target_3.getLeftOperand().(LogicalOrExpr).getLeftOperand().(EQExpr).getRightOperand().(Literal).getValue()="0"
		and target_3.getLeftOperand().(LogicalOrExpr).getRightOperand().(FunctionCall).getTarget().hasName("BN_is_zero")
		and target_3.getLeftOperand().(LogicalOrExpr).getRightOperand().(FunctionCall).getType().hasName("int")
		and target_3.getLeftOperand().(LogicalOrExpr).getRightOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="field"
		and target_3.getLeftOperand().(LogicalOrExpr).getRightOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getType().hasName("BIGNUM *")
		and target_3.getLeftOperand().(LogicalOrExpr).getRightOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vgroup
		and target_3.getRightOperand().(FunctionCall).getTarget().hasName("BN_is_negative")
		and target_3.getRightOperand().(FunctionCall).getType().hasName("int")
		and target_3.getRightOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="field"
		and target_3.getRightOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getType().hasName("BIGNUM *")
		and target_3.getRightOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vgroup)
}

predicate func_5(Function func) {
	exists(FunctionCall target_5 |
		target_5.getTarget().hasName("ERR_put_error")
		and target_5.getType().hasName("void")
		and target_5.getArgument(0).(Literal).getValue()="16"
		and target_5.getArgument(1).(Literal).getValue()="111"
		and target_5.getArgument(2).(Literal).getValue()="103"
		and target_5.getArgument(3).(StringLiteral).getValue()="crypto/ec/ec_lib.c"
		and target_5.getArgument(4).(Literal).getValue()="340"
		and target_5.getEnclosingFunction() = func)
}

predicate func_7(Parameter vgroup, Parameter vorder) {
	exists(LogicalOrExpr target_7 |
		target_7.getType().hasName("int")
		and target_7.getLeftOperand().(LogicalOrExpr).getType().hasName("int")
		and target_7.getLeftOperand().(LogicalOrExpr).getLeftOperand().(LogicalOrExpr).getType().hasName("int")
		and target_7.getLeftOperand().(LogicalOrExpr).getLeftOperand().(LogicalOrExpr).getLeftOperand().(EQExpr).getType().hasName("int")
		and target_7.getLeftOperand().(LogicalOrExpr).getLeftOperand().(LogicalOrExpr).getLeftOperand().(EQExpr).getLeftOperand().(VariableAccess).getTarget()=vorder
		and target_7.getLeftOperand().(LogicalOrExpr).getLeftOperand().(LogicalOrExpr).getLeftOperand().(EQExpr).getRightOperand().(Literal).getValue()="0"
		and target_7.getLeftOperand().(LogicalOrExpr).getLeftOperand().(LogicalOrExpr).getRightOperand().(FunctionCall).getTarget().hasName("BN_is_zero")
		and target_7.getLeftOperand().(LogicalOrExpr).getLeftOperand().(LogicalOrExpr).getRightOperand().(FunctionCall).getType().hasName("int")
		and target_7.getLeftOperand().(LogicalOrExpr).getLeftOperand().(LogicalOrExpr).getRightOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vorder
		and target_7.getLeftOperand().(LogicalOrExpr).getRightOperand().(FunctionCall).getTarget().hasName("BN_is_negative")
		and target_7.getLeftOperand().(LogicalOrExpr).getRightOperand().(FunctionCall).getType().hasName("int")
		and target_7.getLeftOperand().(LogicalOrExpr).getRightOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vorder
		and target_7.getRightOperand().(GTExpr).getType().hasName("int")
		and target_7.getRightOperand().(GTExpr).getGreaterOperand().(FunctionCall).getTarget().hasName("BN_num_bits")
		and target_7.getRightOperand().(GTExpr).getGreaterOperand().(FunctionCall).getType().hasName("int")
		and target_7.getRightOperand().(GTExpr).getGreaterOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vorder
		and target_7.getRightOperand().(GTExpr).getLesserOperand().(AddExpr).getType().hasName("int")
		and target_7.getRightOperand().(GTExpr).getLesserOperand().(AddExpr).getLeftOperand().(FunctionCall).getTarget().hasName("BN_num_bits")
		and target_7.getRightOperand().(GTExpr).getLesserOperand().(AddExpr).getLeftOperand().(FunctionCall).getType().hasName("int")
		and target_7.getRightOperand().(GTExpr).getLesserOperand().(AddExpr).getLeftOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="field"
		and target_7.getRightOperand().(GTExpr).getLesserOperand().(AddExpr).getLeftOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vgroup
		and target_7.getRightOperand().(GTExpr).getLesserOperand().(AddExpr).getRightOperand().(Literal).getValue()="1")
}

predicate func_8(Function func) {
	exists(BlockStmt target_8 |
		target_8.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ERR_put_error")
		and target_8.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getType().hasName("void")
		and target_8.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(Literal).getValue()="16"
		and target_8.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="111"
		and target_8.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(Literal).getValue()="122"
		and target_8.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(StringLiteral).getValue()="crypto/ec/ec_lib.c"
		and target_8.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(4).(Literal).getValue()="351"
		and target_8.getStmt(1).(ReturnStmt).getExpr().(Literal).getValue()="0"
		and target_8.getEnclosingFunction() = func)
}

predicate func_9(Parameter vcofactor) {
	exists(IfStmt target_9 |
		target_9.getCondition().(LogicalAndExpr).getType().hasName("int")
		and target_9.getCondition().(LogicalAndExpr).getLeftOperand().(NEExpr).getType().hasName("int")
		and target_9.getCondition().(LogicalAndExpr).getLeftOperand().(NEExpr).getLeftOperand().(VariableAccess).getTarget()=vcofactor
		and target_9.getCondition().(LogicalAndExpr).getLeftOperand().(NEExpr).getRightOperand().(Literal).getValue()="0"
		and target_9.getCondition().(LogicalAndExpr).getRightOperand().(FunctionCall).getTarget().hasName("BN_is_negative")
		and target_9.getCondition().(LogicalAndExpr).getRightOperand().(FunctionCall).getType().hasName("int")
		and target_9.getCondition().(LogicalAndExpr).getRightOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vcofactor
		and target_9.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ERR_put_error")
		and target_9.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getType().hasName("void")
		and target_9.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(Literal).getValue()="16"
		and target_9.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="111"
		and target_9.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(Literal).getValue()="164"
		and target_9.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(StringLiteral).getValue()="crypto/ec/ec_lib.c"
		and target_9.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(4).(Literal).getValue()="361"
		and target_9.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(Literal).getValue()="0")
}

predicate func_10(Parameter vgroup, Parameter vcofactor) {
	exists(IfStmt target_10 |
		target_10.getCondition().(LogicalAndExpr).getType().hasName("int")
		and target_10.getCondition().(LogicalAndExpr).getLeftOperand().(NEExpr).getType().hasName("int")
		and target_10.getCondition().(LogicalAndExpr).getLeftOperand().(NEExpr).getLeftOperand().(VariableAccess).getTarget()=vcofactor
		and target_10.getCondition().(LogicalAndExpr).getLeftOperand().(NEExpr).getRightOperand().(Literal).getValue()="0"
		and target_10.getCondition().(LogicalAndExpr).getRightOperand().(NotExpr).getType().hasName("int")
		and target_10.getCondition().(LogicalAndExpr).getRightOperand().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("BN_is_zero")
		and target_10.getCondition().(LogicalAndExpr).getRightOperand().(NotExpr).getOperand().(FunctionCall).getType().hasName("int")
		and target_10.getCondition().(LogicalAndExpr).getRightOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vcofactor
		and target_10.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(NotExpr).getType().hasName("int")
		and target_10.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("BN_copy")
		and target_10.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="cofactor"
		and target_10.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vgroup
		and target_10.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vcofactor
		and target_10.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(ReturnStmt).getExpr().(Literal).getValue()="0"
		and target_10.getElse().(IfStmt).getCondition().(NotExpr).getType().hasName("int")
		and target_10.getElse().(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("ec_guess_cofactor")
		and target_10.getElse().(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getType().hasName("int")
		and target_10.getElse().(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vgroup
		and target_10.getElse().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("BN_set_word")
		and target_10.getElse().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="cofactor"
		and target_10.getElse().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vgroup
		and target_10.getElse().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="0"
		and target_10.getElse().(IfStmt).getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(Literal).getValue()="0")
}

predicate func_12(Parameter vgroup, Parameter vorder) {
	exists(IfStmt target_12 |
		target_12.getCondition().(NotExpr).getType().hasName("int")
		and target_12.getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("BN_copy")
		and target_12.getCondition().(NotExpr).getOperand().(FunctionCall).getType().hasName("BIGNUM *")
		and target_12.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="order"
		and target_12.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getType().hasName("BIGNUM *")
		and target_12.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vgroup
		and target_12.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vorder
		and target_12.getThen().(ReturnStmt).getExpr().(Literal).getValue()="0")
}

predicate func_13(Parameter vgroup) {
	exists(PointerFieldAccess target_13 |
		target_13.getTarget().getName()="order"
		and target_13.getType().hasName("BIGNUM *")
		and target_13.getQualifier().(VariableAccess).getTarget()=vgroup)
}

predicate func_14(Parameter vcofactor) {
	exists(NEExpr target_14 |
		target_14.getType().hasName("int")
		and target_14.getLeftOperand().(VariableAccess).getTarget()=vcofactor
		and target_14.getRightOperand().(Literal).getValue()="0")
}

predicate func_15(Parameter vgroup) {
	exists(ExprStmt target_15 |
		target_15.getExpr().(FunctionCall).getTarget().hasName("BN_set_word")
		and target_15.getExpr().(FunctionCall).getType().hasName("int")
		and target_15.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="cofactor"
		and target_15.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getType().hasName("BIGNUM *")
		and target_15.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vgroup
		and target_15.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="0")
}

predicate func_17(Function func) {
	exists(Literal target_17 |
		target_17.getValue()="0"
		and target_17.getEnclosingFunction() = func)
}

from Function func, Parameter vgroup, Parameter vorder, Parameter vcofactor
where
func_0(func)
and func_2(func)
and not func_3(vgroup)
and not func_5(func)
and not func_7(vgroup, vorder)
and not func_8(func)
and not func_9(vcofactor)
and not func_10(vgroup, vcofactor)
and func_12(vgroup, vorder)
and func_13(vgroup)
and func_14(vcofactor)
and func_15(vgroup)
and func_17(func)
and vgroup.getType().hasName("EC_GROUP *")
and vorder.getType().hasName("const BIGNUM *")
and vcofactor.getType().hasName("const BIGNUM *")
and vgroup.getParentScope+() = func
and vorder.getParentScope+() = func
and vcofactor.getParentScope+() = func
select func, vgroup, vorder, vcofactor
