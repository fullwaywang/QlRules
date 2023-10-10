/**
 * @name linux-89c6efa61f5709327ecfa24bff18e57a4e80c7fa-i2c_smbus_xfer_emulated
 * @id cpp/linux/89c6efa61f5709327ecfa24bff18e57a4e80c7fa/i2c-smbus-xfer-emulated
 * @description linux-89c6efa61f5709327ecfa24bff18e57a4e80c7fa-i2c_smbus_xfer_emulated 
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func) {
	exists(StringLiteral target_0 |
		target_0.getValue()="Invalid block write size %d\n"
		and not target_0.getValue()="Invalid block %s size %d\n"
		and target_0.getEnclosingFunction() = func)
}

predicate func_5(Parameter vread_write_298, Parameter vdata_299, Variable vmsg_311) {
	exists(ExprStmt target_5 |
		target_5.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="len"
		and target_5.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vmsg_311
		and target_5.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_5.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="block"
		and target_5.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_299
		and target_5.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_5.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(Literal).getValue()="1"
		and target_5.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vread_write_298
		and target_5.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="1")
}

predicate func_6(Variable vmsg_311) {
	exists(ArrayExpr target_6 |
		target_6.getArrayBase().(VariableAccess).getTarget()=vmsg_311
		and target_6.getArrayOffset().(Literal).getValue()="0")
}

predicate func_8(Function func) {
	exists(ReturnStmt target_8 |
		target_8.getExpr().(UnaryMinusExpr).getValue()="-22"
		and target_8.getExpr().(UnaryMinusExpr).getOperand().(Literal).getValue()="22"
		and target_8.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(RelationalOperation).getGreaterOperand() instanceof ValueFieldAccess
		and target_8.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(RelationalOperation).getLesserOperand() instanceof AddExpr
		and target_8.getEnclosingFunction() = func)
}

predicate func_9(Parameter vread_write_298, Parameter vdata_299, Variable vmsgbuf0_305, Variable vi_308) {
	exists(ForStmt target_9 |
		target_9.getInitialization().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vi_308
		and target_9.getInitialization().(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="1"
		and target_9.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vi_308
		and target_9.getCondition().(RelationalOperation).getGreaterOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="block"
		and target_9.getCondition().(RelationalOperation).getGreaterOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_299
		and target_9.getCondition().(RelationalOperation).getGreaterOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_9.getUpdate().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vi_308
		and target_9.getStmt().(ExprStmt).getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vmsgbuf0_305
		and target_9.getStmt().(ExprStmt).getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_308
		and target_9.getStmt().(ExprStmt).getExpr().(AssignExpr).getRValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="block"
		and target_9.getStmt().(ExprStmt).getExpr().(AssignExpr).getRValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_299
		and target_9.getStmt().(ExprStmt).getExpr().(AssignExpr).getRValue().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_308
		and target_9.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vread_write_298
		and target_9.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="1")
}

predicate func_10(Function func) {
	exists(Literal target_10 |
		target_10.getValue()="1"
		and target_10.getEnclosingFunction() = func)
}

predicate func_11(Function func) {
	exists(Literal target_11 |
		target_11.getValue()="32"
		and target_11.getEnclosingFunction() = func)
}

predicate func_13(Parameter vadapter_296) {
	exists(AddExpr target_13 |
		target_13.getValue()="33"
		and target_13.getAnOperand() instanceof Literal
		and target_13.getAnOperand() instanceof Literal
		and target_13.getParent().(GTExpr).getGreaterOperand().(ValueFieldAccess).getTarget().getName()="len"
		and target_13.getParent().(GTExpr).getGreaterOperand().(ValueFieldAccess).getQualifier() instanceof ArrayExpr
		and target_13.getParent().(GTExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("dev_err")
		and target_13.getParent().(GTExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="dev"
		and target_13.getParent().(GTExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vadapter_296
		and target_13.getParent().(GTExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1) instanceof StringLiteral
		and target_13.getParent().(GTExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2) instanceof ArrayExpr
		and target_13.getParent().(GTExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1) instanceof ReturnStmt)
}

predicate func_15(Parameter vdata_299) {
	exists(PointerFieldAccess target_15 |
		target_15.getTarget().getName()="block"
		and target_15.getQualifier().(VariableAccess).getTarget()=vdata_299)
}

from Function func, Parameter vadapter_296, Parameter vread_write_298, Parameter vdata_299, Variable vmsgbuf0_305, Variable vi_308, Variable vmsg_311
where
func_0(func)
and func_5(vread_write_298, vdata_299, vmsg_311)
and func_6(vmsg_311)
and func_8(func)
and func_9(vread_write_298, vdata_299, vmsgbuf0_305, vi_308)
and func_10(func)
and func_11(func)
and func_13(vadapter_296)
and vadapter_296.getType().hasName("i2c_adapter *")
and vread_write_298.getType().hasName("char")
and vdata_299.getType().hasName("i2c_smbus_data *")
and func_15(vdata_299)
and vmsgbuf0_305.getType().hasName("unsigned char[35]")
and vi_308.getType().hasName("int")
and vmsg_311.getType().hasName("i2c_msg[2]")
and vadapter_296.getParentScope+() = func
and vread_write_298.getParentScope+() = func
and vdata_299.getParentScope+() = func
and vmsgbuf0_305.getParentScope+() = func
and vi_308.getParentScope+() = func
and vmsg_311.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
