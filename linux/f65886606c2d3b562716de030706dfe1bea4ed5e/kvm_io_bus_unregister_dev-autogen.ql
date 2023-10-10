/**
 * @name linux-f65886606c2d3b562716de030706dfe1bea4ed5e-kvm_io_bus_unregister_dev
 * @id cpp/linux/f65886606c2d3b562716de030706dfe1bea4ed5e/kvm-io-bus-unregister-dev
 * @description linux-f65886606c2d3b562716de030706dfe1bea4ed5e-kvm_io_bus_unregister_dev 
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_1(Variable vi_4335, Variable vnew_bus_4336, Variable vbus_4336) {
	exists(ForStmt target_1 |
		target_1.getInitialization().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getType().hasName("int")
		and target_1.getInitialization().(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_1.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getType().hasName("int")
		and target_1.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="dev_count"
		and target_1.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vbus_4336
		and target_1.getUpdate().(PostfixIncrExpr).getOperand().(VariableAccess).getType().hasName("int")
		and target_1.getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getType().hasName("int")
		and target_1.getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vi_4335
		and target_1.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(ContinueStmt).toString() = "continue;"
		and target_1.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("kvm_iodevice_destructor")
		and target_1.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(ValueFieldAccess).getTarget().getName()="dev"
		and target_1.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="range"
		and target_1.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vbus_4336
		and target_1.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(VariableAccess).getType().hasName("int")
		and target_1.getStmt().(BlockStmt).getStmt(2) instanceof LabelStmt
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(VariableAccess).getTarget()=vnew_bus_4336)
}

predicate func_4(Function func) {
	exists(ExprStmt target_4 |
		target_4.getExpr().(FunctionCall).getTarget().hasName("printk")
		and target_4.getExpr().(FunctionCall).getArgument(0).(StringLiteral).getValue()="3kvm: failed to shrink bus, removing it completely\n"
		and target_4.getParent().(BlockStmt).getParent().(IfStmt).getCondition() instanceof NotExpr
		and target_4.getEnclosingFunction() = func)
}

predicate func_5(Variable vi_4335, Variable vnew_bus_4336, Variable vbus_4336, Function func) {
	exists(ExprStmt target_5 |
		target_5.getExpr().(FunctionCall).getTarget().hasName("__memcpy")
		and target_5.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vnew_bus_4336
		and target_5.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vbus_4336
		and target_5.getExpr().(FunctionCall).getArgument(2).(AddExpr).getAnOperand().(SizeofExprOperator).getValue()="8"
		and target_5.getExpr().(FunctionCall).getArgument(2).(AddExpr).getAnOperand().(SizeofExprOperator).getExprOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vbus_4336
		and target_5.getExpr().(FunctionCall).getArgument(2).(AddExpr).getAnOperand().(MulExpr).getLeftOperand().(VariableAccess).getTarget()=vi_4335
		and target_5.getExpr().(FunctionCall).getArgument(2).(AddExpr).getAnOperand().(MulExpr).getRightOperand().(SizeofTypeOperator).getType() instanceof LongType
		and target_5.getExpr().(FunctionCall).getArgument(2).(AddExpr).getAnOperand().(MulExpr).getRightOperand().(SizeofTypeOperator).getValue()="24"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_5)
}

predicate func_6(Variable vnew_bus_4336, Function func) {
	exists(ExprStmt target_6 |
		target_6.getExpr().(PostfixDecrExpr).getOperand().(PointerFieldAccess).getTarget().getName()="dev_count"
		and target_6.getExpr().(PostfixDecrExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vnew_bus_4336
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_6)
}

predicate func_7(Variable vi_4335, Variable vnew_bus_4336, Variable vbus_4336, Function func) {
	exists(ExprStmt target_7 |
		target_7.getExpr().(FunctionCall).getTarget().hasName("__memcpy")
		and target_7.getExpr().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="range"
		and target_7.getExpr().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vnew_bus_4336
		and target_7.getExpr().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vi_4335
		and target_7.getExpr().(FunctionCall).getArgument(1).(PointerArithmeticOperation).getAnOperand().(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="range"
		and target_7.getExpr().(FunctionCall).getArgument(1).(PointerArithmeticOperation).getAnOperand().(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vbus_4336
		and target_7.getExpr().(FunctionCall).getArgument(1).(PointerArithmeticOperation).getAnOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vi_4335
		and target_7.getExpr().(FunctionCall).getArgument(1).(PointerArithmeticOperation).getAnOperand().(Literal).getValue()="1"
		and target_7.getExpr().(FunctionCall).getArgument(2).(MulExpr).getLeftOperand().(SubExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="dev_count"
		and target_7.getExpr().(FunctionCall).getArgument(2).(MulExpr).getLeftOperand().(SubExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vnew_bus_4336
		and target_7.getExpr().(FunctionCall).getArgument(2).(MulExpr).getLeftOperand().(SubExpr).getRightOperand().(VariableAccess).getTarget()=vi_4335
		and target_7.getExpr().(FunctionCall).getArgument(2).(MulExpr).getRightOperand().(SizeofTypeOperator).getType() instanceof LongType
		and target_7.getExpr().(FunctionCall).getArgument(2).(MulExpr).getRightOperand().(SizeofTypeOperator).getValue()="24"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_7)
}

predicate func_8(Function func) {
	exists(LabelStmt target_8 |
		target_8.toString() = "label ...:"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_8)
}

predicate func_12(Variable vi_4335, Variable vbus_4336) {
	exists(EqualityOperation target_12 |
		target_12.getAnOperand().(VariableAccess).getTarget()=vi_4335
		and target_12.getAnOperand().(PointerFieldAccess).getTarget().getName()="dev_count"
		and target_12.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vbus_4336
		and target_12.getParent().(IfStmt).getThen().(ReturnStmt).toString() = "return ...")
}

predicate func_13(Variable vbus_4336) {
	exists(PointerDereferenceExpr target_13 |
		target_13.getOperand().(VariableAccess).getTarget()=vbus_4336)
}

from Function func, Variable vi_4335, Variable vnew_bus_4336, Variable vbus_4336
where
not func_1(vi_4335, vnew_bus_4336, vbus_4336)
and func_4(func)
and func_5(vi_4335, vnew_bus_4336, vbus_4336, func)
and func_6(vnew_bus_4336, func)
and func_7(vi_4335, vnew_bus_4336, vbus_4336, func)
and func_8(func)
and vi_4335.getType().hasName("int")
and func_12(vi_4335, vbus_4336)
and vnew_bus_4336.getType().hasName("kvm_io_bus *")
and vbus_4336.getType().hasName("kvm_io_bus *")
and func_13(vbus_4336)
and vi_4335.getParentScope+() = func
and vnew_bus_4336.getParentScope+() = func
and vbus_4336.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
