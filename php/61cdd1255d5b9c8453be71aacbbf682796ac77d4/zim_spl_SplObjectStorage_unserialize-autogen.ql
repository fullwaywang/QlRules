/**
 * @name php-61cdd1255d5b9c8453be71aacbbf682796ac77d4-zim_spl_SplObjectStorage_unserialize
 * @id cpp/php/61cdd1255d5b9c8453be71aacbbf682796ac77d4/zim-spl-SplObjectStorage-unserialize
 * @description php-61cdd1255d5b9c8453be71aacbbf682796ac77d4-ext/spl/spl_observer.c-zim_spl_SplObjectStorage_unserialize CVE-2016-7480
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

/*predicate func_1(Variable ventry_745, EqualityOperation target_6, AddressOfExpr target_8, AddressOfExpr target_9) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="type_info"
		and target_1.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="u1"
		and target_1.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerDereferenceExpr).getOperand().(AddressOfExpr).getOperand().(VariableAccess).getTarget()=ventry_745
		and target_1.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getElse().(BlockStmt).getStmt(0)=target_1
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_6
		and target_8.getOperand().(VariableAccess).getLocation().isBefore(target_1.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerDereferenceExpr).getOperand().(AddressOfExpr).getOperand().(VariableAccess).getLocation())
		and target_1.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerDereferenceExpr).getOperand().(AddressOfExpr).getOperand().(VariableAccess).getLocation().isBefore(target_9.getOperand().(VariableAccess).getLocation()))
}

*/
predicate func_2(Variable ventry_745, EqualityOperation target_4, AddressOfExpr target_10, AddressOfExpr target_11) {
	exists(ExprStmt target_2 |
		target_2.getExpr().(FunctionCall).getTarget().hasName("_zval_ptr_dtor")
		and target_2.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=ventry_745
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0)=target_2
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_4
		and target_10.getOperand().(VariableAccess).getLocation().isBefore(target_2.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getLocation())
		and target_2.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getLocation().isBefore(target_11.getOperand().(VariableAccess).getLocation()))
}

predicate func_3(Variable vinf_745, EqualityOperation target_4, AddressOfExpr target_12) {
	exists(ExprStmt target_3 |
		target_3.getExpr().(FunctionCall).getTarget().hasName("_zval_ptr_dtor")
		and target_3.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vinf_745
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1)=target_3
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_4
		and target_3.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getLocation().isBefore(target_12.getOperand().(VariableAccess).getLocation()))
}

predicate func_4(Variable ventry_745, BlockStmt target_13, EqualityOperation target_4) {
		target_4.getAnOperand().(FunctionCall).getTarget().hasName("zval_get_type")
		and target_4.getAnOperand().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=ventry_745
		and target_4.getAnOperand().(Literal).getValue()="8"
		and target_4.getParent().(IfStmt).getThen()=target_13
}

predicate func_5(Variable ventry_745, EqualityOperation target_4, ExprStmt target_5) {
		target_5.getExpr().(FunctionCall).getTarget().hasName("_zval_ptr_dtor")
		and target_5.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=ventry_745
		and target_5.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_4
}

predicate func_6(Variable vp_743, BlockStmt target_14, EqualityOperation target_6) {
		target_6.getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vp_743
		and target_6.getAnOperand().(CharLiteral).getValue()="44"
		and target_6.getParent().(IfStmt).getThen()=target_14
}

predicate func_7(EqualityOperation target_6, Function func, DoStmt target_7) {
		target_7.getCondition().(Literal).getValue()="0"
		and target_7.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="type_info"
		and target_7.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="u1"
		and target_7.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_7.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_6
		and target_7.getEnclosingFunction() = func
}

predicate func_8(Variable ventry_745, AddressOfExpr target_8) {
		target_8.getOperand().(VariableAccess).getTarget()=ventry_745
}

predicate func_9(Variable ventry_745, AddressOfExpr target_9) {
		target_9.getOperand().(VariableAccess).getTarget()=ventry_745
}

predicate func_10(Variable ventry_745, AddressOfExpr target_10) {
		target_10.getOperand().(VariableAccess).getTarget()=ventry_745
}

predicate func_11(Variable ventry_745, AddressOfExpr target_11) {
		target_11.getOperand().(VariableAccess).getTarget()=ventry_745
}

predicate func_12(Variable vinf_745, AddressOfExpr target_12) {
		target_12.getOperand().(VariableAccess).getTarget()=vinf_745
}

predicate func_13(BlockStmt target_13) {
		target_13.getStmt(0) instanceof ExprStmt
}

predicate func_14(Variable vp_743, Variable ventry_745, Variable vinf_745, BlockStmt target_14) {
		target_14.getStmt(0).(ExprStmt).getExpr().(PrefixIncrExpr).getOperand().(VariableAccess).getTarget()=vp_743
		and target_14.getStmt(1).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("php_var_unserialize")
		and target_14.getStmt(1).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vinf_745
		and target_14.getStmt(1).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vp_743
		and target_14.getStmt(1).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(2).(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget().getType().hasName("const unsigned char *")
		and target_14.getStmt(1).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(2).(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget().getType().hasName("size_t")
		and target_14.getStmt(1).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(3).(AddressOfExpr).getOperand().(VariableAccess).getTarget().getType().hasName("php_unserialize_data_t")
		and target_14.getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("_zval_ptr_dtor")
		and target_14.getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=ventry_745
}

from Function func, Variable vp_743, Variable ventry_745, Variable vinf_745, EqualityOperation target_4, ExprStmt target_5, EqualityOperation target_6, DoStmt target_7, AddressOfExpr target_8, AddressOfExpr target_9, AddressOfExpr target_10, AddressOfExpr target_11, AddressOfExpr target_12, BlockStmt target_13, BlockStmt target_14
where
not func_2(ventry_745, target_4, target_10, target_11)
and not func_3(vinf_745, target_4, target_12)
and func_4(ventry_745, target_13, target_4)
and func_5(ventry_745, target_4, target_5)
and func_6(vp_743, target_14, target_6)
and func_7(target_6, func, target_7)
and func_8(ventry_745, target_8)
and func_9(ventry_745, target_9)
and func_10(ventry_745, target_10)
and func_11(ventry_745, target_11)
and func_12(vinf_745, target_12)
and func_13(target_13)
and func_14(vp_743, ventry_745, vinf_745, target_14)
and vp_743.getType().hasName("const unsigned char *")
and ventry_745.getType().hasName("zval")
and vinf_745.getType().hasName("zval")
and vp_743.(LocalVariable).getFunction() = func
and ventry_745.(LocalVariable).getFunction() = func
and vinf_745.(LocalVariable).getFunction() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
