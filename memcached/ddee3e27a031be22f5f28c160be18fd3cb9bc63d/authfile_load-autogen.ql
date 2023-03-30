/**
 * @name memcached-ddee3e27a031be22f5f28c160be18fd3cb9bc63d-authfile_load
 * @id cpp/memcached/ddee3e27a031be22f5f28c160be18fd3cb9bc63d-authfile-load
 * @description memcached-ddee3e27a031be22f5f28c160be18fd3cb9bc63d-authfile_load CVE-2021-37519
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vfound_52, BlockStmt target_7, ExprStmt target_10, NotExpr target_11, VariableAccess target_0) {
		target_0.getTarget()=vfound_52
		and target_0.getParent().(IfStmt).getThen()=target_7
		and target_10.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_0.getLocation())
		and target_0.getLocation().isBefore(target_11.getOperand().(VariableAccess).getLocation())
}

predicate func_1(Function func) {
	exists(AddExpr target_1 |
		target_1.getAnOperand() instanceof ValueFieldAccess
		and target_1.getAnOperand().(Literal).getValue()="1"
		and target_1.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("calloc")
		and target_1.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(Literal).getValue()="1"
		and target_1.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(1) instanceof ValueFieldAccess
		and target_1.getEnclosingFunction() = func)
}

predicate func_2(Variable vauth_cur_46, EqualityOperation target_12, LogicalAndExpr target_9) {
	exists(ConditionalExpr target_2 |
		target_2.getCondition().(RelationalOperation).getLesserOperand().(PointerArithmeticOperation).getLeftOperand().(VariableAccess).getType().hasName("char *")
		and target_2.getCondition().(RelationalOperation).getLesserOperand().(PointerArithmeticOperation).getRightOperand().(VariableAccess).getTarget()=vauth_cur_46
		and target_2.getCondition().(RelationalOperation).getGreaterOperand() instanceof Literal
		and target_2.getThen().(PointerArithmeticOperation).getLeftOperand().(VariableAccess).getType().hasName("char *")
		and target_2.getThen().(PointerArithmeticOperation).getRightOperand().(VariableAccess).getTarget()=vauth_cur_46
		and target_2.getElse().(Literal).getValue()="256"
		and target_2.getParent().(FunctionCall).getParent().(NEExpr).getAnOperand().(FunctionCall).getTarget().hasName("fgets")
		and target_2.getParent().(FunctionCall).getParent().(NEExpr).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vauth_cur_46
		and target_2.getParent().(FunctionCall).getParent().(NEExpr).getAnOperand().(FunctionCall).getArgument(1) instanceof Literal
		and target_2.getParent().(FunctionCall).getParent().(NEExpr).getAnOperand().(FunctionCall).getArgument(2).(VariableAccess).getTarget().getType().hasName("FILE *")
		and target_12.getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_2.getCondition().(RelationalOperation).getLesserOperand().(PointerArithmeticOperation).getRightOperand().(VariableAccess).getLocation()))
}

predicate func_3(Variable vauth_cur_46, Variable ventry_cur_47, Variable vx_51, Variable vfound_52, LogicalAndExpr target_9, ExprStmt target_13, ExprStmt target_14, IfStmt target_15) {
	exists(IfStmt target_3 |
		target_3.getCondition().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vauth_cur_46
		and target_3.getCondition().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getType().hasName("int")
		and target_3.getCondition().(EqualityOperation).getAnOperand().(CharLiteral).getValue()="0"
		and target_3.getElse().(IfStmt).getCondition() instanceof EqualityOperation
		and target_3.getElse().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="user"
		and target_3.getElse().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=ventry_cur_47
		and target_3.getElse().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vauth_cur_46
		and target_3.getElse().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="ulen"
		and target_3.getElse().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=ventry_cur_47
		and target_3.getElse().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vx_51
		and target_3.getElse().(IfStmt).getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="pass"
		and target_3.getElse().(IfStmt).getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=ventry_cur_47
		and target_3.getElse().(IfStmt).getThen().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vfound_52
		and target_3.getElse().(IfStmt).getThen().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="1"
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_9
		and target_3.getCondition().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getLocation().isBefore(target_13.getExpr().(AssignExpr).getRValue().(AddressOfExpr).getOperand().(ArrayExpr).getArrayBase().(VariableAccess).getLocation())
		and target_3.getElse().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_14.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_3.getElse().(IfStmt).getThen().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_15.getCondition().(VariableAccess).getLocation()))
}

predicate func_4(Variable vsb_32, ValueFieldAccess target_4) {
		target_4.getTarget().getName()="st_size"
		and target_4.getQualifier().(VariableAccess).getTarget()=vsb_32
}

/*predicate func_5(Variable vauth_cur_46, Variable vx_51, Variable vfound_52, BlockStmt target_16, NotExpr target_5) {
		target_5.getOperand().(VariableAccess).getTarget()=vfound_52
		and target_5.getParent().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vauth_cur_46
		and target_5.getParent().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vx_51
		and target_5.getParent().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(CharLiteral).getValue()="58"
		and target_5.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen()=target_16
}

*/
/*predicate func_6(Variable vauth_cur_46, Variable vx_51, Variable vfound_52, BlockStmt target_16, EqualityOperation target_6) {
		target_6.getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vauth_cur_46
		and target_6.getAnOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vx_51
		and target_6.getAnOperand().(CharLiteral).getValue()="58"
		and target_6.getParent().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(VariableAccess).getTarget()=vfound_52
		and target_6.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen()=target_16
}

*/
predicate func_7(Variable vauth_cur_46, Variable ventry_cur_47, Variable vx_51, LogicalAndExpr target_9, BlockStmt target_7) {
		target_7.getStmt(0).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vauth_cur_46
		and target_7.getStmt(0).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vx_51
		and target_7.getStmt(0).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(CharLiteral).getValue()="10"
		and target_7.getStmt(0).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vauth_cur_46
		and target_7.getStmt(0).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vx_51
		and target_7.getStmt(0).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(CharLiteral).getValue()="13"
		and target_7.getStmt(0).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vauth_cur_46
		and target_7.getStmt(0).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vx_51
		and target_7.getStmt(0).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(CharLiteral).getValue()="0"
		and target_7.getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="plen"
		and target_7.getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=ventry_cur_47
		and target_7.getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(SubExpr).getLeftOperand().(VariableAccess).getTarget()=vx_51
		and target_7.getParent().(IfStmt).getParent().(IfStmt).getCondition()=target_9
}

predicate func_9(BlockStmt target_16, Function func, LogicalAndExpr target_9) {
		target_9.getAnOperand() instanceof NotExpr
		and target_9.getAnOperand() instanceof EqualityOperation
		and target_9.getParent().(IfStmt).getThen()=target_16
		and target_9.getEnclosingFunction() = func
}

predicate func_10(Variable vfound_52, ExprStmt target_10) {
		target_10.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vfound_52
		and target_10.getExpr().(AssignExpr).getRValue().(Literal).getValue()="1"
}

predicate func_11(Variable vfound_52, NotExpr target_11) {
		target_11.getOperand().(VariableAccess).getTarget()=vfound_52
}

predicate func_12(Variable vauth_cur_46, EqualityOperation target_12) {
		target_12.getAnOperand().(FunctionCall).getTarget().hasName("fgets")
		and target_12.getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vauth_cur_46
		and target_12.getAnOperand().(FunctionCall).getArgument(1) instanceof Literal
		and target_12.getAnOperand().(FunctionCall).getArgument(2).(VariableAccess).getTarget().getType().hasName("FILE *")
		and target_12.getAnOperand().(Literal).getValue()="0"
}

predicate func_13(Variable vauth_cur_46, Variable ventry_cur_47, Variable vx_51, ExprStmt target_13) {
		target_13.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="pass"
		and target_13.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=ventry_cur_47
		and target_13.getExpr().(AssignExpr).getRValue().(AddressOfExpr).getOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vauth_cur_46
		and target_13.getExpr().(AssignExpr).getRValue().(AddressOfExpr).getOperand().(ArrayExpr).getArrayOffset().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vx_51
		and target_13.getExpr().(AssignExpr).getRValue().(AddressOfExpr).getOperand().(ArrayExpr).getArrayOffset().(AddExpr).getAnOperand().(Literal).getValue()="1"
}

predicate func_14(Variable ventry_cur_47, Variable vx_51, ExprStmt target_14) {
		target_14.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="plen"
		and target_14.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=ventry_cur_47
		and target_14.getExpr().(AssignExpr).getRValue().(SubExpr).getLeftOperand().(VariableAccess).getTarget()=vx_51
		and target_14.getExpr().(AssignExpr).getRValue().(SubExpr).getRightOperand().(AddExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="ulen"
		and target_14.getExpr().(AssignExpr).getRValue().(SubExpr).getRightOperand().(AddExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=ventry_cur_47
		and target_14.getExpr().(AssignExpr).getRValue().(SubExpr).getRightOperand().(AddExpr).getAnOperand().(Literal).getValue()="1"
}

predicate func_15(Variable vfound_52, IfStmt target_15) {
		target_15.getCondition().(VariableAccess).getTarget()=vfound_52
		and target_15.getThen() instanceof BlockStmt
}

predicate func_16(Variable vauth_cur_46, Variable ventry_cur_47, Variable vx_51, BlockStmt target_16) {
		target_16.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="user"
		and target_16.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=ventry_cur_47
		and target_16.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vauth_cur_46
		and target_16.getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="ulen"
		and target_16.getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=ventry_cur_47
		and target_16.getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vx_51
}

from Function func, Variable vsb_32, Variable vauth_cur_46, Variable ventry_cur_47, Variable vx_51, Variable vfound_52, VariableAccess target_0, ValueFieldAccess target_4, BlockStmt target_7, LogicalAndExpr target_9, ExprStmt target_10, NotExpr target_11, EqualityOperation target_12, ExprStmt target_13, ExprStmt target_14, IfStmt target_15, BlockStmt target_16
where
func_0(vfound_52, target_7, target_10, target_11, target_0)
and not func_1(func)
and not func_2(vauth_cur_46, target_12, target_9)
and not func_3(vauth_cur_46, ventry_cur_47, vx_51, vfound_52, target_9, target_13, target_14, target_15)
and func_4(vsb_32, target_4)
and func_7(vauth_cur_46, ventry_cur_47, vx_51, target_9, target_7)
and func_9(target_16, func, target_9)
and func_10(vfound_52, target_10)
and func_11(vfound_52, target_11)
and func_12(vauth_cur_46, target_12)
and func_13(vauth_cur_46, ventry_cur_47, vx_51, target_13)
and func_14(ventry_cur_47, vx_51, target_14)
and func_15(vfound_52, target_15)
and func_16(vauth_cur_46, ventry_cur_47, vx_51, target_16)
and vsb_32.getType().hasName("stat")
and vauth_cur_46.getType().hasName("char *")
and ventry_cur_47.getType().hasName("auth_t *")
and vx_51.getType().hasName("int")
and vfound_52.getType().hasName("int")
and vsb_32.getParentScope+() = func
and vauth_cur_46.getParentScope+() = func
and ventry_cur_47.getParentScope+() = func
and vx_51.getParentScope+() = func
and vfound_52.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
