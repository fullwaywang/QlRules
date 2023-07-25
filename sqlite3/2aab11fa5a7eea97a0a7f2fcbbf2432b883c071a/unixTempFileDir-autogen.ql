/**
 * @name sqlite3-2aab11fa5a7eea97a0a7f2fcbbf2432b883c071a-unixTempFileDir
 * @id cpp/sqlite3/2aab11fa5a7eea97a0a7f2fcbbf2432b883c071a/unixTempFileDir
 * @description sqlite3-2aab11fa5a7eea97a0a7f2fcbbf2432b883c071a-src/os_unix.c-unixTempFileDir CVE-2016-6153
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func) {
	exists(Initializer target_0 |
		target_0.getExpr() instanceof Literal
		and target_0.getExpr().getEnclosingFunction() = func)
}

predicate func_1(Variable vi_5415) {
	exists(WhileStmt target_1 |
		target_1.getCondition().(Literal).getValue()="1"
		and target_1.getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand() instanceof EqualityOperation
		and target_1.getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand() instanceof VariableCall
		and target_1.getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_1.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0) instanceof ReturnStmt
		and target_1.getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vi_5415
		and target_1.getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(RelationalOperation).getLesserOperand() instanceof DivExpr
		and target_1.getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr() instanceof AssignExpr)
}

/*predicate func_2(Variable vzDir_5417, AssignExpr target_7, VariableCall target_8) {
	exists(LogicalAndExpr target_2 |
		target_2.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vzDir_5417
		and target_2.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand() instanceof Literal
		and target_2.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand() instanceof VariableCall
		and target_2.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_2.getAnOperand().(LogicalAndExpr).getAnOperand() instanceof EqualityOperation
		and target_2.getAnOperand().(EqualityOperation).getAnOperand() instanceof VariableCall
		and target_2.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_2.getParent().(IfStmt).getThen() instanceof ContinueStmt
		and target_7.getLValue().(VariableAccess).getLocation().isBefore(target_2.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getLocation())
		and target_2.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getLocation().isBefore(target_8.getArgument(0).(VariableAccess).getLocation()))
}

*/
/*predicate func_4(Variable vi_5415) {
	exists(RelationalOperation target_4 |
		 (target_4 instanceof GEExpr or target_4 instanceof LEExpr)
		and target_4.getGreaterOperand().(VariableAccess).getTarget()=vi_5415
		and target_4.getLesserOperand() instanceof DivExpr
		and target_4.getParent().(IfStmt).getThen() instanceof ContinueStmt)
}

*/
/*predicate func_5(VariableCall target_8, Function func) {
	exists(BreakStmt target_5 |
		target_5.getParent().(IfStmt).getCondition()=target_8
		and target_5.getEnclosingFunction() = func)
}

*/
predicate func_6(Variable vi_5415, BlockStmt target_24, DivExpr target_6) {
		target_6.getValue()="6"
		and target_6.getParent().(LEExpr).getLesserOperand().(VariableAccess).getTarget()=vi_5415
		and target_6.getParent().(LEExpr).getParent().(ForStmt).getStmt()=target_24
}

predicate func_7(Variable vzDir_5417, Variable vi_5415, Variable vazDirs_5407, AssignExpr target_7) {
		target_7.getLValue().(VariableAccess).getTarget()=vzDir_5417
		and target_7.getRValue().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vazDirs_5407
		and target_7.getRValue().(ArrayExpr).getArrayOffset().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vi_5415
}

predicate func_8(Variable vbuf_5416, Variable vzDir_5417, Variable vaSyscall, VariableCall target_8) {
		target_8.getExpr().(ValueFieldAccess).getTarget().getName()="pCurrent"
		and target_8.getExpr().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vaSyscall
		and target_8.getExpr().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(Literal).getValue()="4"
		and target_8.getArgument(0).(VariableAccess).getTarget()=vzDir_5417
		and target_8.getArgument(1).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vbuf_5416
}

predicate func_9(Variable vbuf_5416, EqualityOperation target_9) {
		target_9.getAnOperand().(BitwiseAndExpr).getLeftOperand().(ValueFieldAccess).getTarget().getName()="st_mode"
		and target_9.getAnOperand().(BitwiseAndExpr).getLeftOperand().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vbuf_5416
		and target_9.getAnOperand().(BitwiseAndExpr).getRightOperand().(Literal).getValue()="61440"
		and target_9.getAnOperand().(Literal).getValue()="16384"
		and target_9.getParent().(NotExpr).getParent().(IfStmt).getThen() instanceof ContinueStmt
}

predicate func_10(Variable vzDir_5417, Variable vaSyscall, VariableCall target_10) {
		target_10.getExpr().(ValueFieldAccess).getTarget().getName()="pCurrent"
		and target_10.getExpr().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vaSyscall
		and target_10.getExpr().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(Literal).getValue()="2"
		and target_10.getArgument(0).(VariableAccess).getTarget()=vzDir_5417
		and target_10.getArgument(1).(OctalLiteral).getValue()="3"
}

predicate func_11(Variable vzDir_5417, ReturnStmt target_11) {
		target_11.getExpr().(VariableAccess).getTarget()=vzDir_5417
}

/*predicate func_12(Variable vi_5415, BlockStmt target_24, VariableAccess target_12) {
		target_12.getTarget()=vi_5415
		and target_12.getParent().(LEExpr).getGreaterOperand().(DivExpr).getValue()="6"
		and target_12.getParent().(LEExpr).getParent().(ForStmt).getStmt()=target_24
}

*/
predicate func_13(Variable vzDir_5417, VariableAccess target_13) {
		target_13.getTarget()=vzDir_5417
		and target_13.getParent().(EQExpr).getAnOperand().(Literal).getValue()="0"
		and target_13.getParent().(EQExpr).getParent().(IfStmt).getThen() instanceof ContinueStmt
}

predicate func_16(Variable vzDir_5417, Variable vi_5415, Function func, ForStmt target_16) {
		target_16.getInitialization().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vi_5415
		and target_16.getInitialization().(ExprStmt).getExpr().(AssignExpr).getRValue() instanceof Literal
		and target_16.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vi_5415
		and target_16.getCondition().(RelationalOperation).getGreaterOperand() instanceof DivExpr
		and target_16.getUpdate() instanceof AssignExpr
		and target_16.getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vzDir_5417
		and target_16.getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(EqualityOperation).getAnOperand() instanceof Literal
		and target_16.getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition() instanceof VariableCall
		and target_16.getStmt().(BlockStmt).getStmt(2).(IfStmt).getCondition().(NotExpr).getOperand() instanceof EqualityOperation
		and target_16.getStmt().(BlockStmt).getStmt(3).(IfStmt).getCondition() instanceof VariableCall
		and target_16.getStmt().(BlockStmt).getStmt(4) instanceof ReturnStmt
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_16
}

/*predicate func_17(Variable vi_5415, AssignExpr target_17) {
		target_17.getLValue().(VariableAccess).getTarget()=vi_5415
		and target_17.getRValue() instanceof Literal
}

*/
/*predicate func_18(EqualityOperation target_25, Function func, ContinueStmt target_18) {
		target_18.getParent().(IfStmt).getCondition()=target_25
		and target_18.getEnclosingFunction() = func
}

*/
/*predicate func_19(VariableCall target_8, Function func, ContinueStmt target_19) {
		target_19.getParent().(IfStmt).getCondition()=target_8
		and target_19.getEnclosingFunction() = func
}

*/
/*predicate func_20(Function func, IfStmt target_20) {
		target_20.getCondition().(NotExpr).getOperand() instanceof EqualityOperation
		and target_20.getEnclosingFunction() = func
}

*/
/*predicate func_21(Function func, IfStmt target_21) {
		target_21.getCondition() instanceof VariableCall
		and target_21.getEnclosingFunction() = func
}

*/
predicate func_24(Variable vzDir_5417, BlockStmt target_24) {
		target_24.getStmt(0).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vzDir_5417
		and target_24.getStmt(0).(IfStmt).getCondition().(EqualityOperation).getAnOperand() instanceof Literal
		and target_24.getStmt(0).(IfStmt).getThen() instanceof ContinueStmt
		and target_24.getStmt(1).(IfStmt).getCondition() instanceof VariableCall
		and target_24.getStmt(1).(IfStmt).getThen() instanceof ContinueStmt
}

predicate func_25(Variable vzDir_5417, EqualityOperation target_25) {
		target_25.getAnOperand().(VariableAccess).getTarget()=vzDir_5417
		and target_25.getAnOperand() instanceof Literal
}

from Function func, Variable vbuf_5416, Variable vzDir_5417, Variable vaSyscall, Variable vi_5415, Variable vazDirs_5407, DivExpr target_6, AssignExpr target_7, VariableCall target_8, EqualityOperation target_9, VariableCall target_10, ReturnStmt target_11, VariableAccess target_13, ForStmt target_16, BlockStmt target_24, EqualityOperation target_25
where
not func_0(func)
and not func_1(vi_5415)
and func_6(vi_5415, target_24, target_6)
and func_7(vzDir_5417, vi_5415, vazDirs_5407, target_7)
and func_8(vbuf_5416, vzDir_5417, vaSyscall, target_8)
and func_9(vbuf_5416, target_9)
and func_10(vzDir_5417, vaSyscall, target_10)
and func_11(vzDir_5417, target_11)
and func_13(vzDir_5417, target_13)
and func_16(vzDir_5417, vi_5415, func, target_16)
and func_24(vzDir_5417, target_24)
and func_25(vzDir_5417, target_25)
and vbuf_5416.getType().hasName("stat")
and vzDir_5417.getType().hasName("const char *")
and vaSyscall.getType() instanceof ArrayType
and vi_5415.getType().hasName("unsigned int")
and vazDirs_5407.getType().hasName("const char *[]")
and vbuf_5416.(LocalVariable).getFunction() = func
and vzDir_5417.(LocalVariable).getFunction() = func
and not vaSyscall.getParentScope+() = func
and vi_5415.(LocalVariable).getFunction() = func
and vazDirs_5407.(LocalVariable).getFunction() = func
select func, "function relativepath is " + func.getFile(), "function startline is " + func.getLocation().getStartLine()
