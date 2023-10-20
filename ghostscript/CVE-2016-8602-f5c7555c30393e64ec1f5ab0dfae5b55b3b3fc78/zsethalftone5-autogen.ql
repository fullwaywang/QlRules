/**
 * @name ghostscript-f5c7555c30393e64ec1f5ab0dfae5b55b3b3fc78-zsethalftone5
 * @id cpp/ghostscript/f5c7555c30393e64ec1f5ab0dfae5b55b3b3fc78/zsethalftone5
 * @description ghostscript-f5c7555c30393e64ec1f5ab0dfae5b55b3b3fc78-psi/zht2.c-zsethalftone5 CVE-2016-8602
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vi_ctx_p_69, AddressOfExpr target_9, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(RelationalOperation).getLesserOperand().(FunctionCall).getTarget().hasName("ref_stack_count")
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(ValueFieldAccess).getTarget().getName()="stack"
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="op_stack"
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vi_ctx_p_69
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(Literal).getValue()="2"
		and (func.getEntryPoint().(BlockStmt).getStmt(22)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(22).getFollowingStmt()=target_0)
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_9.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_2(Variable vop_71, NotExpr target_10, Function func) {
	exists(IfStmt target_2 |
		target_2.getCondition().(NotExpr).getOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(AddressOfExpr).getOperand().(ValueFieldAccess).getTarget().getName()="type_attrs"
		and target_2.getCondition().(NotExpr).getOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(AddressOfExpr).getOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="tas"
		and target_2.getCondition().(NotExpr).getOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="1"
		and target_2.getThen().(ReturnStmt).getExpr().(FunctionCall).getTarget().hasName("check_type_failed")
		and target_2.getThen().(ReturnStmt).getExpr().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getLeftOperand().(VariableAccess).getTarget()=vop_71
		and target_2.getThen().(ReturnStmt).getExpr().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getRightOperand().(Literal).getValue()="1"
		and (func.getEntryPoint().(BlockStmt).getStmt(24)=target_2 or func.getEntryPoint().(BlockStmt).getStmt(24).getFollowingStmt()=target_2)
		and target_2.getThen().(ReturnStmt).getExpr().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getLeftOperand().(VariableAccess).getLocation().isBefore(target_10.getOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(AddressOfExpr).getOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_4(Variable vspace_index_92, ExprStmt target_11, Function func) {
	exists(ExprStmt target_4 |
		target_4.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vspace_index_92
		and target_4.getExpr().(AssignExpr).getRValue() instanceof BinaryBitwiseOperation
		and (func.getEntryPoint().(BlockStmt).getStmt(26)=target_4 or func.getEntryPoint().(BlockStmt).getStmt(26).getFollowingStmt()=target_4)
		and target_4.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_11.getExpr().(AssignExpr).getRValue().(ArrayExpr).getArrayOffset().(VariableAccess).getLocation()))
}

predicate func_5(Variable vop_71, FunctionCall target_5) {
		target_5.getTarget().hasName("dict_first")
		and target_5.getArgument(0).(VariableAccess).getTarget()=vop_71
}

predicate func_6(Variable vop_71, BinaryBitwiseOperation target_6) {
		target_6.getLeftOperand().(BitwiseAndExpr).getLeftOperand().(ValueFieldAccess).getTarget().getName()="type_attrs"
		and target_6.getLeftOperand().(BitwiseAndExpr).getLeftOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="tas"
		and target_6.getLeftOperand().(BitwiseAndExpr).getLeftOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerArithmeticOperation).getLeftOperand().(VariableAccess).getTarget()=vop_71
		and target_6.getLeftOperand().(BitwiseAndExpr).getLeftOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerArithmeticOperation).getRightOperand().(Literal).getValue()="1"
		and target_6.getLeftOperand().(BitwiseAndExpr).getRightOperand().(BinaryBitwiseOperation).getValue()="12"
		and target_6.getRightOperand().(Literal).getValue()="2"
}

predicate func_7(Function func, Initializer target_7) {
		target_7.getExpr() instanceof FunctionCall
		and target_7.getExpr().getEnclosingFunction() = func
}

predicate func_8(Function func, Initializer target_8) {
		target_8.getExpr() instanceof BinaryBitwiseOperation
		and target_8.getExpr().getEnclosingFunction() = func
}

predicate func_9(Parameter vi_ctx_p_69, AddressOfExpr target_9) {
		target_9.getOperand().(PointerFieldAccess).getTarget().getName()="memory"
		and target_9.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vi_ctx_p_69
}

predicate func_10(Variable vop_71, NotExpr target_10) {
		target_10.getOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(AddressOfExpr).getOperand().(ValueFieldAccess).getTarget().getName()="type_attrs"
		and target_10.getOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(AddressOfExpr).getOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="tas"
		and target_10.getOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(AddressOfExpr).getOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vop_71
		and target_10.getOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="1"
}

predicate func_11(Variable vspace_index_92, ExprStmt target_11) {
		target_11.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("gs_memory_t *")
		and target_11.getExpr().(AssignExpr).getRValue().(ArrayExpr).getArrayBase().(ValueFieldAccess).getTarget().getName()="indexed"
		and target_11.getExpr().(AssignExpr).getRValue().(ArrayExpr).getArrayBase().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="memories"
		and target_11.getExpr().(AssignExpr).getRValue().(ArrayExpr).getArrayBase().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="spaces"
		and target_11.getExpr().(AssignExpr).getRValue().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vspace_index_92
}

from Function func, Parameter vi_ctx_p_69, Variable vop_71, Variable vdict_enum_85, Variable vspace_index_92, FunctionCall target_5, BinaryBitwiseOperation target_6, Initializer target_7, Initializer target_8, AddressOfExpr target_9, NotExpr target_10, ExprStmt target_11
where
not func_0(vi_ctx_p_69, target_9, func)
and not func_2(vop_71, target_10, func)
and not func_4(vspace_index_92, target_11, func)
and func_5(vop_71, target_5)
and func_6(vop_71, target_6)
and func_7(func, target_7)
and func_8(func, target_8)
and func_9(vi_ctx_p_69, target_9)
and func_10(vop_71, target_10)
and func_11(vspace_index_92, target_11)
and vi_ctx_p_69.getType().hasName("i_ctx_t *")
and vop_71.getType().hasName("os_ptr")
and vdict_enum_85.getType().hasName("int")
and vspace_index_92.getType().hasName("int")
and vi_ctx_p_69.getFunction() = func
and vop_71.(LocalVariable).getFunction() = func
and vdict_enum_85.(LocalVariable).getFunction() = func
and vspace_index_92.(LocalVariable).getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
