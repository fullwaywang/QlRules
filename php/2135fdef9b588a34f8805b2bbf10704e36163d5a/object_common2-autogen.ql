/**
 * @name php-2135fdef9b588a34f8805b2bbf10704e36163d5a-object_common2
 * @id cpp/php/2135fdef9b588a34f8805b2bbf10704e36163d5a/object-common2
 * @description php-2135fdef9b588a34f8805b2bbf10704e36163d5a-ext/standard/var_unserializer.c-object_common2 CVE-2016-7124
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func) {
	exists(AssignExpr target_0 |
		target_0.getLValue().(VariableAccess).getType().hasName("zend_bool")
		and target_0.getRValue() instanceof LogicalAndExpr
		and target_0.getEnclosingFunction() = func)
}

predicate func_1(NotExpr target_14, Function func) {
	exists(IfStmt target_1 |
		target_1.getCondition().(VariableAccess).getType().hasName("zend_bool")
		and target_1.getThen().(BlockStmt).getStmt(0) instanceof DoStmt
		and target_1.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignOrExpr).getLValue().(ValueFieldAccess).getTarget().getName()="flags"
		and target_1.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignOrExpr).getLValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="v"
		and target_1.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignOrExpr).getLValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="u"
		and target_1.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignOrExpr).getRValue().(BinaryBitwiseOperation).getValue()="8"
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0)=target_1
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_14
		and target_1.getEnclosingFunction() = func)
}

/*predicate func_2(LogicalAndExpr target_12, Function func) {
	exists(ExprStmt target_2 |
		target_2.getExpr().(AssignOrExpr).getLValue().(ValueFieldAccess).getTarget().getName()="flags"
		and target_2.getExpr().(AssignOrExpr).getLValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="v"
		and target_2.getExpr().(AssignOrExpr).getLValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="u"
		and target_2.getExpr().(AssignOrExpr).getLValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="gc"
		and target_2.getExpr().(AssignOrExpr).getLValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="obj"
		and target_2.getExpr().(AssignOrExpr).getRValue().(BinaryBitwiseOperation).getValue()="8"
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1)=target_2
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_12
		and target_2.getEnclosingFunction() = func)
}

*/
predicate func_5(Variable vretval_455, LogicalAndExpr target_12, AddressOfExpr target_15) {
	exists(IfStmt target_5 |
		target_5.getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand() instanceof FunctionCall
		and target_5.getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getTarget().hasName("zval_get_type")
		and target_5.getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vretval_455
		and target_5.getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_5.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignOrExpr).getLValue().(ValueFieldAccess).getTarget().getName()="flags"
		and target_5.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignOrExpr).getLValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="v"
		and target_5.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignOrExpr).getLValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="u"
		and target_5.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignOrExpr).getRValue().(BinaryBitwiseOperation).getValue()="8"
		and target_5.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(2)=target_5
		and target_5.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_12
		and target_5.getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getLocation().isBefore(target_15.getOperand().(VariableAccess).getLocation()))
}

predicate func_6(Variable v__s_472, LogicalAndExpr target_12, DoStmt target_6) {
		target_6.getCondition().(Literal).getValue()="0"
		and target_6.getStmt().(BlockStmt).getStmt(0).(DoStmt).getCondition().(Literal).getValue()="0"
		and target_6.getStmt().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="str"
		and target_6.getStmt().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=v__s_472
		and target_6.getStmt().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="type_info"
		and target_6.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_12
}

predicate func_7(Variable vbasic_globals, LogicalAndExpr target_12, ExprStmt target_7) {
		target_7.getExpr().(PostfixIncrExpr).getOperand().(ValueFieldAccess).getTarget().getName()="serialize_lock"
		and target_7.getExpr().(PostfixIncrExpr).getOperand().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vbasic_globals
		and target_7.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_12
}

predicate func_8(Variable vbasic_globals, LogicalAndExpr target_12, ExprStmt target_8) {
		target_8.getExpr().(PostfixDecrExpr).getOperand().(ValueFieldAccess).getTarget().getName()="serialize_lock"
		and target_8.getExpr().(PostfixDecrExpr).getOperand().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vbasic_globals
		and target_8.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_12
}

predicate func_9(Variable vfname_456, LogicalAndExpr target_12, ExprStmt target_9) {
		target_9.getExpr().(FunctionCall).getTarget().hasName("_zval_dtor")
		and target_9.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vfname_456
		and target_9.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_12
}

predicate func_10(Variable vretval_455, LogicalAndExpr target_12, ExprStmt target_10) {
		target_10.getExpr().(FunctionCall).getTarget().hasName("_zval_dtor")
		and target_10.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vretval_455
		and target_10.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_12
}

predicate func_11(Parameter vrval_453, Function func, DoStmt target_11) {
		target_11.getCondition().(Literal).getValue()="0"
		and target_11.getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(FunctionCall).getTarget().hasName("__builtin_expect")
		and target_11.getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(FunctionCall).getArgument(1).(Literal).getValue()="0"
		and target_11.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vrval_453
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_11
}

predicate func_12(Parameter vrval_453, Variable vbasic_globals, BlockStmt target_16, LogicalAndExpr target_12) {
		target_12.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="ce"
		and target_12.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="obj"
		and target_12.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="value"
		and target_12.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vrval_453
		and target_12.getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getTarget().getName()="incomplete_class"
		and target_12.getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vbasic_globals
		and target_12.getAnOperand().(FunctionCall).getTarget().hasName("zend_hash_str_exists")
		and target_12.getAnOperand().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="function_table"
		and target_12.getAnOperand().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="ce"
		and target_12.getAnOperand().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="obj"
		and target_12.getAnOperand().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="value"
		and target_12.getAnOperand().(FunctionCall).getArgument(1).(StringLiteral).getValue()="__wakeup"
		and target_12.getAnOperand().(FunctionCall).getArgument(2).(SubExpr).getValue()="8"
		and target_12.getParent().(IfStmt).getThen()=target_16
}

predicate func_13(Parameter vrval_453, Variable vretval_455, Variable vfname_456, Variable vcompiler_globals, FunctionCall target_13) {
		target_13.getTarget().hasName("call_user_function_ex")
		and target_13.getArgument(0).(ValueFieldAccess).getTarget().getName()="function_table"
		and target_13.getArgument(0).(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vcompiler_globals
		and target_13.getArgument(1).(VariableAccess).getTarget()=vrval_453
		and target_13.getArgument(2).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vfname_456
		and target_13.getArgument(3).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vretval_455
		and target_13.getArgument(4).(Literal).getValue()="0"
		and target_13.getArgument(5).(Literal).getValue()="0"
		and target_13.getArgument(6).(Literal).getValue()="1"
		and target_13.getArgument(7).(Literal).getValue()="0"
}

predicate func_14(Parameter vrval_453, NotExpr target_14) {
		target_14.getOperand().(FunctionCall).getTarget().hasName("process_nested_data")
		and target_14.getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vrval_453
		and target_14.getOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget().getType().hasName("const unsigned char **")
		and target_14.getOperand().(FunctionCall).getArgument(2).(VariableAccess).getTarget().getType().hasName("const unsigned char *")
		and target_14.getOperand().(FunctionCall).getArgument(3).(VariableAccess).getTarget().getType().hasName("php_unserialize_data_t *")
		and target_14.getOperand().(FunctionCall).getArgument(4).(VariableAccess).getTarget().getType().hasName("HashTable *")
		and target_14.getOperand().(FunctionCall).getArgument(5).(VariableAccess).getTarget().getType().hasName("HashTable *")
		and target_14.getOperand().(FunctionCall).getArgument(6).(VariableAccess).getTarget().getType().hasName("zend_long")
		and target_14.getOperand().(FunctionCall).getArgument(7).(Literal).getValue()="1"
}

predicate func_15(Variable vretval_455, AddressOfExpr target_15) {
		target_15.getOperand().(VariableAccess).getTarget()=vretval_455
}

predicate func_16(BlockStmt target_16) {
		target_16.getStmt(0) instanceof DoStmt
		and target_16.getStmt(1) instanceof ExprStmt
		and target_16.getStmt(2).(ExprStmt).getExpr() instanceof FunctionCall
		and target_16.getStmt(3) instanceof ExprStmt
		and target_16.getStmt(4) instanceof ExprStmt
}

from Function func, Parameter vrval_453, Variable vretval_455, Variable vfname_456, Variable vbasic_globals, Variable v__s_472, Variable vcompiler_globals, DoStmt target_6, ExprStmt target_7, ExprStmt target_8, ExprStmt target_9, ExprStmt target_10, DoStmt target_11, LogicalAndExpr target_12, FunctionCall target_13, NotExpr target_14, AddressOfExpr target_15, BlockStmt target_16
where
not func_0(func)
and not func_1(target_14, func)
and not func_5(vretval_455, target_12, target_15)
and func_6(v__s_472, target_12, target_6)
and func_7(vbasic_globals, target_12, target_7)
and func_8(vbasic_globals, target_12, target_8)
and func_9(vfname_456, target_12, target_9)
and func_10(vretval_455, target_12, target_10)
and func_11(vrval_453, func, target_11)
and func_12(vrval_453, vbasic_globals, target_16, target_12)
and func_13(vrval_453, vretval_455, vfname_456, vcompiler_globals, target_13)
and func_14(vrval_453, target_14)
and func_15(vretval_455, target_15)
and func_16(target_16)
and vrval_453.getType().hasName("zval *")
and vretval_455.getType().hasName("zval")
and vfname_456.getType().hasName("zval")
and vbasic_globals.getType().hasName("php_basic_globals")
and v__s_472.getType().hasName("zend_string *")
and vcompiler_globals.getType().hasName("_zend_compiler_globals")
and vrval_453.getFunction() = func
and vretval_455.(LocalVariable).getFunction() = func
and vfname_456.(LocalVariable).getFunction() = func
and not vbasic_globals.getParentScope+() = func
and v__s_472.(LocalVariable).getFunction() = func
and not vcompiler_globals.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
