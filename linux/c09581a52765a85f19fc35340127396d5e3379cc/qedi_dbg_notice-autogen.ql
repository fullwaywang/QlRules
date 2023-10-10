/**
 * @name linux-c09581a52765a85f19fc35340127396d5e3379cc-qedi_dbg_notice
 * @id cpp/linux/c09581a52765a85f19fc35340127396d5e3379cc/qedi_dbg_notice
 * @description linux-c09581a52765a85f19fc35340127396d5e3379cc-qedi_dbg_notice 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_2(Function func) {
	exists(DeclStmt target_2 |
		target_2.getDeclarationEntry(0).(VariableDeclarationEntry).getType() instanceof ArrayType
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_2)
}

predicate func_3(Variable vnfunc_73) {
	exists(FunctionCall target_3 |
		target_3.getTarget().hasName("__memset")
		and target_3.getArgument(0).(VariableAccess).getTarget()=vnfunc_73
		and target_3.getArgument(1).(Literal).getValue()="0"
		and target_3.getArgument(2).(SizeofExprOperator).getValue()="32"
		and target_3.getArgument(2).(SizeofExprOperator).getExprOperand().(VariableAccess).getTarget()=vnfunc_73)
}

predicate func_4(Parameter vfunc_68, Variable vnfunc_73) {
	exists(FunctionCall target_4 |
		target_4.getTarget().hasName("__memcpy")
		and target_4.getArgument(0).(VariableAccess).getTarget()=vnfunc_73
		and target_4.getArgument(1).(VariableAccess).getTarget()=vfunc_68
		and target_4.getArgument(2).(SubExpr).getValue()="31"
		and target_4.getArgument(2).(SubExpr).getLeftOperand().(SizeofExprOperator).getValue()="32"
		and target_4.getArgument(2).(SubExpr).getLeftOperand().(SizeofExprOperator).getExprOperand().(VariableAccess).getTarget()=vnfunc_73
		and target_4.getArgument(2).(SubExpr).getRightOperand().(Literal).getValue()="1")
}

predicate func_5(Parameter vline_68, Variable vvaf_72, Variable vnfunc_73, Parameter vqedi_68) {
	exists(ExprStmt target_5 |
		target_5.getExpr().(FunctionCall).getTarget().hasName("printk")
		and target_5.getExpr().(FunctionCall).getArgument(0).(StringLiteral).getValue()="5[%s]:[%s:%d]:%d: %pV"
		and target_5.getExpr().(FunctionCall).getArgument(1).(FunctionCall).getTarget().hasName("dev_name")
		and target_5.getExpr().(FunctionCall).getArgument(1).(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="dev"
		and target_5.getExpr().(FunctionCall).getArgument(1).(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="pdev"
		and target_5.getExpr().(FunctionCall).getArgument(1).(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vqedi_68
		and target_5.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vnfunc_73
		and target_5.getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vline_68
		and target_5.getExpr().(FunctionCall).getArgument(4).(PointerFieldAccess).getTarget().getName()="host_no"
		and target_5.getExpr().(FunctionCall).getArgument(4).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vqedi_68
		and target_5.getExpr().(FunctionCall).getArgument(5).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vvaf_72
		and target_5.getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(FunctionCall).getTarget().hasName("__builtin_expect")
		and target_5.getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(0).(NotExpr).getOperand().(NotExpr).getOperand().(VariableAccess).getTarget()=vqedi_68
		and target_5.getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(1).(Literal).getValue()="1"
		and target_5.getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(FunctionCall).getTarget().hasName("__builtin_expect")
		and target_5.getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(0).(NotExpr).getOperand().(NotExpr).getOperand().(PointerFieldAccess).getTarget().getName()="pdev"
		and target_5.getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(0).(NotExpr).getOperand().(NotExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vqedi_68
		and target_5.getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(1).(Literal).getValue()="1")
}

predicate func_7(Parameter vline_68, Variable vvaf_72, Variable vnfunc_73, Parameter vqedi_68) {
	exists(ExprStmt target_7 |
		target_7.getExpr().(FunctionCall).getTarget().hasName("printk")
		and target_7.getExpr().(FunctionCall).getArgument(0).(StringLiteral).getValue()="5[0000:00:00.0]:[%s:%d]: %pV"
		and target_7.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vnfunc_73
		and target_7.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vline_68
		and target_7.getExpr().(FunctionCall).getArgument(3).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vvaf_72
		and target_7.getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(FunctionCall).getTarget().hasName("__builtin_expect")
		and target_7.getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(0).(NotExpr).getOperand().(NotExpr).getOperand().(VariableAccess).getTarget()=vqedi_68
		and target_7.getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(1).(Literal).getValue()="1"
		and target_7.getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(FunctionCall).getTarget().hasName("__builtin_expect")
		and target_7.getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(0).(NotExpr).getOperand().(NotExpr).getOperand().(PointerFieldAccess).getTarget().getName()="pdev"
		and target_7.getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(0).(NotExpr).getOperand().(NotExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vqedi_68
		and target_7.getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(1).(Literal).getValue()="1")
}

from Function func, Parameter vfunc_68, Parameter vline_68, Variable vvaf_72, Variable vnfunc_73, Parameter vqedi_68
where
func_2(func)
and func_3(vnfunc_73)
and func_4(vfunc_68, vnfunc_73)
and func_5(vline_68, vvaf_72, vnfunc_73, vqedi_68)
and func_7(vline_68, vvaf_72, vnfunc_73, vqedi_68)
and vfunc_68.getType().hasName("const char *")
and vline_68.getType().hasName("u32")
and vvaf_72.getType().hasName("va_format")
and vnfunc_73.getType().hasName("char[32]")
and vqedi_68.getType().hasName("qedi_dbg_ctx *")
and vfunc_68.getParentScope+() = func
and vline_68.getParentScope+() = func
and vvaf_72.getParentScope+() = func
and vnfunc_73.getParentScope+() = func
and vqedi_68.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
