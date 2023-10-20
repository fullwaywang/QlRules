/**
 * @name redis-dcbfcb916ca1a269b3feef86ee86835294758f84-stringmatchlen
 * @id cpp/redis/dcbfcb916ca1a269b3feef86ee86835294758f84/stringmatchlen
 * @description redis-dcbfcb916ca1a269b3feef86ee86835294758f84-src/util.c-stringmatchlen CVE-2022-36021
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vpatternLen_56, VariableAccess target_0) {
		target_0.getTarget()=vpatternLen_56
		and vpatternLen_56.getIndex() = 1
}

predicate func_1(Parameter vpattern_56, Parameter vpatternLen_56, Parameter vstring_57, Parameter vstringLen_57, Parameter vnocase_57, ReturnStmt target_138, FunctionCall target_1) {
		target_1.getTarget().hasName("stringmatchlen")
		and not target_1.getTarget().hasName("stringmatchlen_impl")
		and target_1.getArgument(0).(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vpattern_56
		and target_1.getArgument(0).(PointerArithmeticOperation).getAnOperand() instanceof Literal
		and target_1.getArgument(1).(SubExpr).getLeftOperand().(VariableAccess).getTarget()=vpatternLen_56
		and target_1.getArgument(1).(SubExpr).getRightOperand() instanceof Literal
		and target_1.getArgument(2).(VariableAccess).getTarget()=vstring_57
		and target_1.getArgument(3).(VariableAccess).getTarget()=vstringLen_57
		and target_1.getArgument(4).(VariableAccess).getTarget()=vnocase_57
		and target_1.getParent().(IfStmt).getThen()=target_138
}

predicate func_2(Parameter vpattern_56, Initializer target_2) {
		target_2.getExpr().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vpattern_56
		and target_2.getExpr().(ArrayExpr).getArrayOffset() instanceof Literal
}

predicate func_3(Parameter vpattern_56, Parameter vpatternLen_56, Parameter vstring_57, Parameter vstringLen_57, Parameter vnocase_57, ReturnStmt target_138) {
	exists(AddressOfExpr target_3 |
		target_3.getOperand().(VariableAccess).getType().hasName("int")
		and target_3.getParent().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vpattern_56
		and target_3.getParent().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand() instanceof Literal
		and target_3.getParent().(FunctionCall).getArgument(1).(SubExpr).getLeftOperand().(VariableAccess).getTarget()=vpatternLen_56
		and target_3.getParent().(FunctionCall).getArgument(1).(SubExpr).getRightOperand() instanceof Literal
		and target_3.getParent().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vstring_57
		and target_3.getParent().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vstringLen_57
		and target_3.getParent().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vnocase_57
		and target_3.getParent().(FunctionCall).getParent().(IfStmt).getThen()=target_138)
}

predicate func_5(Parameter vpatternLen_56, Parameter vstringLen_57, VariableAccess target_5) {
		target_5.getTarget()=vpatternLen_56
		and target_5.getParent().(LogicalAndExpr).getAnOperand().(VariableAccess).getTarget()=vstringLen_57
}

predicate func_6(Parameter vpattern_56, VariableAccess target_6) {
		target_6.getTarget()=vpattern_56
		and target_6.getParent().(ArrayExpr).getArrayOffset() instanceof Literal
}

predicate func_7(Parameter vpattern_56, Parameter vpatternLen_56, Parameter vstringLen_57, WhileStmt target_7) {
		target_7.getCondition().(LogicalAndExpr).getAnOperand().(VariableAccess).getTarget()=vpatternLen_56
		and target_7.getCondition().(LogicalAndExpr).getAnOperand().(VariableAccess).getTarget()=vstringLen_57
		and target_7.getStmt().(BlockStmt).getStmt(0).(BlockStmt).getStmt(0).(SwitchStmt).getExpr().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vpattern_56
		and target_7.getStmt().(BlockStmt).getStmt(0).(BlockStmt).getStmt(0).(SwitchStmt).getExpr().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_7.getStmt().(BlockStmt).getStmt(0).(BlockStmt).getStmt(0).(SwitchStmt).getStmt().(BlockStmt).getStmt(0).(SwitchCase).getExpr().(CharLiteral).getValue()="42"
		and target_7.getStmt().(BlockStmt).getStmt(0).(BlockStmt).getStmt(0).(SwitchStmt).getStmt().(BlockStmt).getStmt(3).(WhileStmt).getCondition().(VariableAccess).getTarget()=vstringLen_57
		and target_7.getStmt().(BlockStmt).getStmt(0).(BlockStmt).getStmt(0).(SwitchStmt).getStmt().(BlockStmt).getStmt(4).(ReturnStmt).getExpr() instanceof Literal
		and target_7.getStmt().(BlockStmt).getStmt(0).(BlockStmt).getStmt(0).(SwitchStmt).getStmt().(BlockStmt).getStmt(6).(SwitchCase).getExpr().(CharLiteral).getValue()="63"
		and target_7.getStmt().(BlockStmt).getStmt(0).(BlockStmt).getStmt(0).(SwitchStmt).getStmt().(BlockStmt).getStmt(10).(SwitchCase).getExpr().(CharLiteral).getValue()="91"
		and target_7.getStmt().(BlockStmt).getStmt(0).(BlockStmt).getStmt(0).(SwitchStmt).getStmt().(BlockStmt).getStmt(12).(SwitchCase).getExpr().(CharLiteral).getValue()="92"
		and target_7.getStmt().(BlockStmt).getStmt(0).(BlockStmt).getStmt(0).(SwitchStmt).getStmt().(BlockStmt).getStmt(14).(SwitchCase).toString() = "default: "
		and target_7.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vpattern_56
		and target_7.getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(PostfixDecrExpr).getOperand().(VariableAccess).getTarget()=vpatternLen_56
		and target_7.getStmt().(BlockStmt).getStmt(3).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vstringLen_57
		and target_7.getStmt().(BlockStmt).getStmt(3).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_7.getStmt().(BlockStmt).getStmt(3).(IfStmt).getThen().(BlockStmt).getStmt(0).(WhileStmt).getCondition().(EqualityOperation).getAnOperand().(CharLiteral).getValue()="42"
}

/*predicate func_8(Parameter vpattern_56, Parameter vpatternLen_56, Parameter vstring_57, Parameter vstringLen_57, Parameter vnocase_57, Variable vnot_83, Variable vmatch_83, SwitchStmt target_8) {
		target_8.getExpr().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vpattern_56
		and target_8.getExpr().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_8.getStmt().(BlockStmt).getStmt(0).(SwitchCase).getExpr().(CharLiteral).getValue()="42"
		and target_8.getStmt().(BlockStmt).getStmt(1).(WhileStmt).getCondition().(LogicalAndExpr).getAnOperand().(VariableAccess).getTarget()=vpatternLen_56
		and target_8.getStmt().(BlockStmt).getStmt(1).(WhileStmt).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vpattern_56
		and target_8.getStmt().(BlockStmt).getStmt(1).(WhileStmt).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="1"
		and target_8.getStmt().(BlockStmt).getStmt(1).(WhileStmt).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(CharLiteral).getValue()="42"
		and target_8.getStmt().(BlockStmt).getStmt(1).(WhileStmt).getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vpattern_56
		and target_8.getStmt().(BlockStmt).getStmt(1).(WhileStmt).getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(PostfixDecrExpr).getOperand().(VariableAccess).getTarget()=vpatternLen_56
		and target_8.getStmt().(BlockStmt).getStmt(2).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vpatternLen_56
		and target_8.getStmt().(BlockStmt).getStmt(2).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="1"
		and target_8.getStmt().(BlockStmt).getStmt(2).(IfStmt).getThen().(ReturnStmt).getExpr().(Literal).getValue()="1"
		and target_8.getStmt().(BlockStmt).getStmt(3).(WhileStmt).getCondition().(VariableAccess).getTarget()=vstringLen_57
		and target_8.getStmt().(BlockStmt).getStmt(3).(WhileStmt).getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition() instanceof FunctionCall
		and target_8.getStmt().(BlockStmt).getStmt(3).(WhileStmt).getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(ReturnStmt).getExpr().(Literal).getValue()="1"
		and target_8.getStmt().(BlockStmt).getStmt(3).(WhileStmt).getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vstring_57
		and target_8.getStmt().(BlockStmt).getStmt(3).(WhileStmt).getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(PostfixDecrExpr).getOperand().(VariableAccess).getTarget()=vstringLen_57
		and target_8.getStmt().(BlockStmt).getStmt(4).(ReturnStmt).getExpr() instanceof Literal
		and target_8.getStmt().(BlockStmt).getStmt(6).(SwitchCase).getExpr().(CharLiteral).getValue()="63"
		and target_8.getStmt().(BlockStmt).getStmt(7).(ExprStmt).getExpr().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vstring_57
		and target_8.getStmt().(BlockStmt).getStmt(8).(ExprStmt).getExpr().(PostfixDecrExpr).getOperand().(VariableAccess).getTarget()=vstringLen_57
		and target_8.getStmt().(BlockStmt).getStmt(10).(SwitchCase).getExpr().(CharLiteral).getValue()="91"
		and target_8.getStmt().(BlockStmt).getStmt(11).(BlockStmt).getStmt(1).(ExprStmt).getExpr().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vpattern_56
		and target_8.getStmt().(BlockStmt).getStmt(11).(BlockStmt).getStmt(2).(ExprStmt).getExpr().(PostfixDecrExpr).getOperand().(VariableAccess).getTarget()=vpatternLen_56
		and target_8.getStmt().(BlockStmt).getStmt(11).(BlockStmt).getStmt(3).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vnot_83
		and target_8.getStmt().(BlockStmt).getStmt(11).(BlockStmt).getStmt(3).(ExprStmt).getExpr().(AssignExpr).getRValue().(EqualityOperation).getAnOperand().(CharLiteral).getValue()="94"
		and target_8.getStmt().(BlockStmt).getStmt(11).(BlockStmt).getStmt(4).(IfStmt).getCondition().(VariableAccess).getTarget()=vnot_83
		and target_8.getStmt().(BlockStmt).getStmt(11).(BlockStmt).getStmt(5).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vmatch_83
		and target_8.getStmt().(BlockStmt).getStmt(11).(BlockStmt).getStmt(5).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_8.getStmt().(BlockStmt).getStmt(11).(BlockStmt).getStmt(6).(BlockStmt).getStmt(0).(WhileStmt).getCondition().(Literal).getValue()="1"
		and target_8.getStmt().(BlockStmt).getStmt(11).(BlockStmt).getStmt(7).(IfStmt).getCondition().(VariableAccess).getTarget()=vnot_83
		and target_8.getStmt().(BlockStmt).getStmt(11).(BlockStmt).getStmt(7).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vmatch_83
		and target_8.getStmt().(BlockStmt).getStmt(11).(BlockStmt).getStmt(8).(IfStmt).getCondition().(NotExpr).getOperand().(VariableAccess).getTarget()=vmatch_83
		and target_8.getStmt().(BlockStmt).getStmt(11).(BlockStmt).getStmt(8).(IfStmt).getThen().(ReturnStmt).getExpr().(Literal).getValue()="0"
		and target_8.getStmt().(BlockStmt).getStmt(11).(BlockStmt).getStmt(9).(ExprStmt).getExpr().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vstring_57
		and target_8.getStmt().(BlockStmt).getStmt(11).(BlockStmt).getStmt(10).(ExprStmt).getExpr().(PostfixDecrExpr).getOperand().(VariableAccess).getTarget()=vstringLen_57
		and target_8.getStmt().(BlockStmt).getStmt(12).(SwitchCase).getExpr().(CharLiteral).getValue()="92"
		and target_8.getStmt().(BlockStmt).getStmt(13).(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vpatternLen_56
		and target_8.getStmt().(BlockStmt).getStmt(13).(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(Literal).getValue()="2"
		and target_8.getStmt().(BlockStmt).getStmt(13).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vpattern_56
		and target_8.getStmt().(BlockStmt).getStmt(13).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(PostfixDecrExpr).getOperand().(VariableAccess).getTarget()=vpatternLen_56
		and target_8.getStmt().(BlockStmt).getStmt(14).(SwitchCase).toString() = "default: "
		and target_8.getStmt().(BlockStmt).getStmt(15).(IfStmt).getCondition().(NotExpr).getOperand().(VariableAccess).getTarget()=vnocase_57
		and target_8.getStmt().(BlockStmt).getStmt(15).(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(ReturnStmt).getExpr().(Literal).getValue()="0"
		and target_8.getStmt().(BlockStmt).getStmt(15).(IfStmt).getElse().(BlockStmt).getStmt(0).(IfStmt).getThen().(ReturnStmt).getExpr().(Literal).getValue()="0"
		and target_8.getStmt().(BlockStmt).getStmt(16).(ExprStmt).getExpr().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vstring_57
		and target_8.getStmt().(BlockStmt).getStmt(17).(ExprStmt).getExpr().(PostfixDecrExpr).getOperand().(VariableAccess).getTarget()=vstringLen_57
}

*/
/*predicate func_9(Function func, SwitchCase target_9) {
		target_9.getExpr().(CharLiteral).getValue()="42"
		and target_9.getEnclosingFunction() = func
}

*/
/*predicate func_10(Parameter vpattern_56, Parameter vpatternLen_56, ArrayExpr target_139, WhileStmt target_10) {
		target_10.getCondition().(LogicalAndExpr).getAnOperand().(VariableAccess).getTarget()=vpatternLen_56
		and target_10.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vpattern_56
		and target_10.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="1"
		and target_10.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(CharLiteral).getValue()="42"
		and target_10.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vpattern_56
		and target_10.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(PostfixDecrExpr).getOperand().(VariableAccess).getTarget()=vpatternLen_56
		and target_10.getParent().(BlockStmt).getParent().(SwitchStmt).getExpr()=target_139
}

*/
predicate func_11(Parameter vpattern_56, PointerArithmeticOperation target_141, ExprStmt target_11) {
		target_11.getExpr().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vpattern_56
		and target_11.getExpr().(PostfixIncrExpr).getOperand().(VariableAccess).getLocation().isBefore(target_141.getAnOperand().(VariableAccess).getLocation())
}

/*predicate func_12(Parameter vpatternLen_56, LogicalAndExpr target_142, EqualityOperation target_143, ExprStmt target_12) {
		target_12.getExpr().(PostfixDecrExpr).getOperand().(VariableAccess).getTarget()=vpatternLen_56
		and target_142.getAnOperand().(VariableAccess).getLocation().isBefore(target_12.getExpr().(PostfixDecrExpr).getOperand().(VariableAccess).getLocation())
		and target_12.getExpr().(PostfixDecrExpr).getOperand().(VariableAccess).getLocation().isBefore(target_143.getAnOperand().(VariableAccess).getLocation())
}

*/
/*predicate func_13(Parameter vpatternLen_56, ArrayExpr target_139, IfStmt target_13) {
		target_13.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vpatternLen_56
		and target_13.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="1"
		and target_13.getThen().(ReturnStmt).getExpr().(Literal).getValue()="1"
		and target_13.getParent().(BlockStmt).getParent().(SwitchStmt).getExpr()=target_139
}

*/
/*predicate func_15(Parameter vstring_57, Parameter vstringLen_57, ArrayExpr target_139, WhileStmt target_15) {
		target_15.getCondition().(VariableAccess).getTarget()=vstringLen_57
		and target_15.getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition() instanceof FunctionCall
		and target_15.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(ReturnStmt).getExpr().(Literal).getValue()="1"
		and target_15.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vstring_57
		and target_15.getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(PostfixDecrExpr).getOperand().(VariableAccess).getTarget()=vstringLen_57
		and target_15.getParent().(BlockStmt).getParent().(SwitchStmt).getExpr()=target_139
}

*/
/*predicate func_16(Function func, IfStmt target_16) {
		target_16.getCondition() instanceof FunctionCall
		and target_16.getThen().(ReturnStmt).getExpr().(Literal).getValue()="1"
		and target_16.getEnclosingFunction() = func
}

*/
/*predicate func_17(Parameter vpattern_56, ExprStmt target_11, ExprStmt target_31, VariableAccess target_17) {
		target_17.getTarget()=vpattern_56
		and target_17.getParent().(PointerAddExpr).getParent().(FunctionCall).getParent().(IfStmt).getCondition() instanceof FunctionCall
		and target_11.getExpr().(PostfixIncrExpr).getOperand().(VariableAccess).getLocation().isBefore(target_17.getLocation())
		and target_17.getLocation().isBefore(target_31.getExpr().(PostfixIncrExpr).getOperand().(VariableAccess).getLocation())
}

*/
/*predicate func_19(Parameter vpatternLen_56, EqualityOperation target_143, ExprStmt target_32, VariableAccess target_19) {
		target_19.getTarget()=vpatternLen_56
		and target_19.getParent().(SubExpr).getParent().(FunctionCall).getParent().(IfStmt).getCondition() instanceof FunctionCall
		and target_143.getAnOperand().(VariableAccess).getLocation().isBefore(target_19.getLocation())
		and target_19.getLocation().isBefore(target_32.getExpr().(PostfixDecrExpr).getOperand().(VariableAccess).getLocation())
}

*/
/*predicate func_21(Parameter vstring_57, FunctionCall target_1, ExprStmt target_26, ExprStmt target_21) {
		target_21.getExpr().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vstring_57
		and target_1.getArgument(2).(VariableAccess).getLocation().isBefore(target_21.getExpr().(PostfixIncrExpr).getOperand().(VariableAccess).getLocation())
		and target_21.getExpr().(PostfixIncrExpr).getOperand().(VariableAccess).getLocation().isBefore(target_26.getExpr().(PostfixIncrExpr).getOperand().(VariableAccess).getLocation())
}

*/
/*predicate func_22(Parameter vstringLen_57, FunctionCall target_1, ExprStmt target_27, ExprStmt target_22) {
		target_22.getExpr().(PostfixDecrExpr).getOperand().(VariableAccess).getTarget()=vstringLen_57
		and target_1.getArgument(3).(VariableAccess).getLocation().isBefore(target_22.getExpr().(PostfixDecrExpr).getOperand().(VariableAccess).getLocation())
		and target_22.getExpr().(PostfixDecrExpr).getOperand().(VariableAccess).getLocation().isBefore(target_27.getExpr().(PostfixDecrExpr).getOperand().(VariableAccess).getLocation())
}

*/
/*predicate func_23(ArrayExpr target_139, Function func, ReturnStmt target_23) {
		target_23.getExpr() instanceof Literal
		and target_23.getParent().(BlockStmt).getParent().(SwitchStmt).getExpr()=target_139
		and target_23.getEnclosingFunction() = func
}

*/
/*predicate func_24(ArrayExpr target_139, Function func, BreakStmt target_24) {
		target_24.getParent().(BlockStmt).getParent().(SwitchStmt).getExpr()=target_139
		and target_24.getEnclosingFunction() = func
}

*/
/*predicate func_25(Function func, SwitchCase target_25) {
		target_25.getExpr().(CharLiteral).getValue()="63"
		and target_25.getEnclosingFunction() = func
}

*/
predicate func_26(Parameter vstring_57, ExprStmt target_26) {
		target_26.getExpr().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vstring_57
}

predicate func_27(Parameter vstringLen_57, ExprStmt target_27) {
		target_27.getExpr().(PostfixDecrExpr).getOperand().(VariableAccess).getTarget()=vstringLen_57
}

/*predicate func_29(Function func, SwitchCase target_29) {
		target_29.getExpr().(CharLiteral).getValue()="91"
		and target_29.getEnclosingFunction() = func
}

*/
predicate func_31(Parameter vpattern_56, ExprStmt target_31) {
		target_31.getExpr().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vpattern_56
}

predicate func_32(Parameter vpatternLen_56, ExprStmt target_32) {
		target_32.getExpr().(PostfixDecrExpr).getOperand().(VariableAccess).getTarget()=vpatternLen_56
}

/*predicate func_33(Parameter vpattern_56, Variable vnot_83, ExprStmt target_33) {
		target_33.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vnot_83
		and target_33.getExpr().(AssignExpr).getRValue().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vpattern_56
		and target_33.getExpr().(AssignExpr).getRValue().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_33.getExpr().(AssignExpr).getRValue().(EqualityOperation).getAnOperand().(CharLiteral).getValue()="94"
}

*/
/*predicate func_34(Parameter vpattern_56, Parameter vpatternLen_56, Variable vnot_83, IfStmt target_34) {
		target_34.getCondition().(VariableAccess).getTarget()=vnot_83
		and target_34.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vpattern_56
		and target_34.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(PostfixDecrExpr).getOperand().(VariableAccess).getTarget()=vpatternLen_56
}

*/
/*predicate func_35(Parameter vpattern_56, ExprStmt target_35) {
		target_35.getExpr().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vpattern_56
}

*/
/*predicate func_36(Parameter vpatternLen_56, ExprStmt target_36) {
		target_36.getExpr().(PostfixDecrExpr).getOperand().(VariableAccess).getTarget()=vpatternLen_56
}

*/
/*predicate func_37(Variable vmatch_83, ExprStmt target_37) {
		target_37.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vmatch_83
		and target_37.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
}

*/
/*predicate func_38(Parameter vpattern_56, Parameter vpatternLen_56, WhileStmt target_38) {
		target_38.getCondition().(Literal).getValue()="1"
		and target_38.getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vpattern_56
		and target_38.getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_38.getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(CharLiteral).getValue()="92"
		and target_38.getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vpatternLen_56
		and target_38.getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="2"
		and target_38.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vpattern_56
		and target_38.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(PostfixDecrExpr).getOperand().(VariableAccess).getTarget()=vpatternLen_56
		and target_38.getStmt().(BlockStmt).getStmt(0).(IfStmt).getElse().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vpattern_56
		and target_38.getStmt().(BlockStmt).getStmt(0).(IfStmt).getElse().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_38.getStmt().(BlockStmt).getStmt(0).(IfStmt).getElse().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(CharLiteral).getValue()="93"
		and target_38.getStmt().(BlockStmt).getStmt(0).(IfStmt).getElse().(IfStmt).getElse().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vpatternLen_56
		and target_38.getStmt().(BlockStmt).getStmt(0).(IfStmt).getElse().(IfStmt).getElse().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_38.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vpattern_56
		and target_38.getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(PostfixDecrExpr).getOperand().(VariableAccess).getTarget()=vpatternLen_56
}

*/
/*predicate func_39(Parameter vpattern_56, Parameter vpatternLen_56, Parameter vstring_57, Parameter vnocase_57, Variable vmatch_83, IfStmt target_39) {
		target_39.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vpattern_56
		and target_39.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_39.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(CharLiteral).getValue()="92"
		and target_39.getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vpatternLen_56
		and target_39.getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="2"
		and target_39.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vpattern_56
		and target_39.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(PostfixDecrExpr).getOperand().(VariableAccess).getTarget()=vpatternLen_56
		and target_39.getThen().(BlockStmt).getStmt(2).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vpattern_56
		and target_39.getThen().(BlockStmt).getStmt(2).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_39.getThen().(BlockStmt).getStmt(2).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vstring_57
		and target_39.getThen().(BlockStmt).getStmt(2).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_39.getThen().(BlockStmt).getStmt(2).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vmatch_83
		and target_39.getThen().(BlockStmt).getStmt(2).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="1"
		and target_39.getElse().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vpattern_56
		and target_39.getElse().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_39.getElse().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(CharLiteral).getValue()="93"
		and target_39.getElse().(IfStmt).getElse().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vpatternLen_56
		and target_39.getElse().(IfStmt).getElse().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_39.getElse().(IfStmt).getElse().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(PostfixDecrExpr).getOperand().(VariableAccess).getTarget()=vpattern_56
		and target_39.getElse().(IfStmt).getElse().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vpatternLen_56
		and target_39.getElse().(IfStmt).getElse().(IfStmt).getElse().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vpatternLen_56
		and target_39.getElse().(IfStmt).getElse().(IfStmt).getElse().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="3"
		and target_39.getElse().(IfStmt).getElse().(IfStmt).getElse().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(CharLiteral).getValue()="45"
		and target_39.getElse().(IfStmt).getElse().(IfStmt).getElse().(IfStmt).getThen().(BlockStmt).getStmt(4).(IfStmt).getCondition().(VariableAccess).getTarget()=vnocase_57
}

*/
/*predicate func_40(Parameter vpattern_56, ExprStmt target_40) {
		target_40.getExpr().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vpattern_56
}

*/
/*predicate func_41(Parameter vpatternLen_56, ExprStmt target_41) {
		target_41.getExpr().(PostfixDecrExpr).getOperand().(VariableAccess).getTarget()=vpatternLen_56
}

*/
/*predicate func_42(Parameter vpattern_56, Parameter vstring_57, Variable vmatch_83, IfStmt target_42) {
		target_42.getCondition().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vpattern_56
		and target_42.getCondition().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_42.getCondition().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vstring_57
		and target_42.getCondition().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_42.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vmatch_83
		and target_42.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="1"
}

*/
/*predicate func_44(Parameter vpattern_56, ExprStmt target_44) {
		target_44.getExpr().(PostfixDecrExpr).getOperand().(VariableAccess).getTarget()=vpattern_56
}

*/
/*predicate func_45(Parameter vpatternLen_56, ExprStmt target_45) {
		target_45.getExpr().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vpatternLen_56
}

*/
/*predicate func_48(Parameter vpattern_56, VariableAccess target_48) {
		target_48.getTarget()=vpattern_56
}

*/
/*predicate func_52(Variable vstart_106, Variable vend_107, Variable vt_110, IfStmt target_52) {
		target_52.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vstart_106
		and target_52.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vend_107
		and target_52.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vstart_106
		and target_52.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vend_107
		and target_52.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vend_107
		and target_52.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vt_110
}

*/
/*predicate func_54(Variable vstart_106, Variable vend_107, ExprStmt target_54) {
		target_54.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vstart_106
		and target_54.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vend_107
}

*/
/*predicate func_55(Variable vend_107, Variable vt_110, ExprStmt target_55) {
		target_55.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vend_107
		and target_55.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vt_110
}

*/
/*predicate func_56(Parameter vnocase_57, Variable vstart_106, Variable vend_107, Variable vc_108, IfStmt target_56) {
		target_56.getCondition().(VariableAccess).getTarget()=vnocase_57
		and target_56.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vstart_106
		and target_56.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vend_107
		and target_56.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vc_108
}

*/
/*predicate func_57(Variable vstart_106, Variable v__res_115, ExprStmt target_57) {
		target_57.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vstart_106
		and target_57.getExpr().(AssignExpr).getRValue().(StmtExpr).getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(RelationalOperation).getValue()="1"
		and target_57.getExpr().(AssignExpr).getRValue().(StmtExpr).getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(VariableAccess).getTarget()=v__res_115
}

*/
/*predicate func_59(Variable vstart_106, Variable v__res_115, IfStmt target_59) {
		target_59.getCondition().(RelationalOperation).getValue()="1"
		and target_59.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(FunctionCall).getTarget().hasName("__builtin_constant_p")
		and target_59.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vstart_106
		and target_59.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=v__res_115
		and target_59.getThen().(BlockStmt).getStmt(0).(IfStmt).getElse().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=v__res_115
		and target_59.getThen().(BlockStmt).getStmt(0).(IfStmt).getElse().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("tolower")
		and target_59.getThen().(BlockStmt).getStmt(0).(IfStmt).getElse().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vstart_106
		and target_59.getElse().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=v__res_115
		and target_59.getElse().(ExprStmt).getExpr().(AssignExpr).getRValue().(ArrayExpr).getArrayBase().(PointerDereferenceExpr).getOperand().(FunctionCall).getTarget().hasName("__ctype_tolower_loc")
		and target_59.getElse().(ExprStmt).getExpr().(AssignExpr).getRValue().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vstart_106
}

*/
/*predicate func_60(Variable vstart_106, Variable v__res_115, Variable v__c_115, IfStmt target_60) {
		target_60.getCondition().(FunctionCall).getTarget().hasName("__builtin_constant_p")
		and target_60.getCondition().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vstart_106
		and target_60.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=v__res_115
		and target_60.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(ConditionalExpr).getThen().(VariableAccess).getTarget()=v__c_115
		and target_60.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(ConditionalExpr).getElse().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=v__c_115
		and target_60.getElse().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=v__res_115
		and target_60.getElse().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("tolower")
		and target_60.getElse().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vstart_106
}

*/
/*predicate func_62(Variable v__res_115, Variable v__c_115, ExprStmt target_62) {
		target_62.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=v__res_115
		and target_62.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=v__c_115
		and target_62.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(UnaryMinusExpr).getValue()="-128"
		and target_62.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=v__c_115
		and target_62.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="255"
		and target_62.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getThen().(VariableAccess).getTarget()=v__c_115
		and target_62.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getElse().(ArrayExpr).getArrayBase().(PointerDereferenceExpr).getOperand().(FunctionCall).getTarget().hasName("__ctype_tolower_loc")
		and target_62.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getElse().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=v__c_115
}

*/
/*predicate func_63(Variable v__res_115, ExprStmt target_63) {
		target_63.getExpr().(VariableAccess).getTarget()=v__res_115
}

*/
/*predicate func_64(Variable vend_107, Variable v__res_116, ExprStmt target_64) {
		target_64.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vend_107
		and target_64.getExpr().(AssignExpr).getRValue().(StmtExpr).getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(RelationalOperation).getValue()="1"
		and target_64.getExpr().(AssignExpr).getRValue().(StmtExpr).getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(VariableAccess).getTarget()=v__res_116
}

*/
/*predicate func_66(Variable vend_107, Variable v__res_116, IfStmt target_66) {
		target_66.getCondition().(RelationalOperation).getValue()="1"
		and target_66.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(FunctionCall).getTarget().hasName("__builtin_constant_p")
		and target_66.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vend_107
		and target_66.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=v__res_116
		and target_66.getThen().(BlockStmt).getStmt(0).(IfStmt).getElse().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=v__res_116
		and target_66.getThen().(BlockStmt).getStmt(0).(IfStmt).getElse().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("tolower")
		and target_66.getThen().(BlockStmt).getStmt(0).(IfStmt).getElse().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vend_107
		and target_66.getElse().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=v__res_116
		and target_66.getElse().(ExprStmt).getExpr().(AssignExpr).getRValue().(ArrayExpr).getArrayBase().(PointerDereferenceExpr).getOperand().(FunctionCall).getTarget().hasName("__ctype_tolower_loc")
		and target_66.getElse().(ExprStmt).getExpr().(AssignExpr).getRValue().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vend_107
}

*/
/*predicate func_67(Variable vend_107, Variable v__res_116, Variable v__c_116, IfStmt target_67) {
		target_67.getCondition().(FunctionCall).getTarget().hasName("__builtin_constant_p")
		and target_67.getCondition().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vend_107
		and target_67.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=v__res_116
		and target_67.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(ConditionalExpr).getThen().(VariableAccess).getTarget()=v__c_116
		and target_67.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(ConditionalExpr).getElse().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=v__c_116
		and target_67.getElse().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=v__res_116
		and target_67.getElse().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("tolower")
		and target_67.getElse().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vend_107
}

*/
/*predicate func_69(Variable v__res_116, Variable v__c_116, ExprStmt target_69) {
		target_69.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=v__res_116
		and target_69.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=v__c_116
		and target_69.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(UnaryMinusExpr).getValue()="-128"
		and target_69.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=v__c_116
		and target_69.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="255"
		and target_69.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getThen().(VariableAccess).getTarget()=v__c_116
		and target_69.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getElse().(ArrayExpr).getArrayBase().(PointerDereferenceExpr).getOperand().(FunctionCall).getTarget().hasName("__ctype_tolower_loc")
		and target_69.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getElse().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=v__c_116
}

*/
/*predicate func_70(Variable v__res_116, ExprStmt target_70) {
		target_70.getExpr().(VariableAccess).getTarget()=v__res_116
}

*/
/*predicate func_71(Variable vc_108, Variable v__res_117, ExprStmt target_71) {
		target_71.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vc_108
		and target_71.getExpr().(AssignExpr).getRValue().(StmtExpr).getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(RelationalOperation).getValue()="1"
		and target_71.getExpr().(AssignExpr).getRValue().(StmtExpr).getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(VariableAccess).getTarget()=v__res_117
}

*/
/*predicate func_73(Variable vc_108, Variable v__res_117, IfStmt target_73) {
		target_73.getCondition().(RelationalOperation).getValue()="1"
		and target_73.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(FunctionCall).getTarget().hasName("__builtin_constant_p")
		and target_73.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vc_108
		and target_73.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=v__res_117
		and target_73.getThen().(BlockStmt).getStmt(0).(IfStmt).getElse().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=v__res_117
		and target_73.getThen().(BlockStmt).getStmt(0).(IfStmt).getElse().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("tolower")
		and target_73.getThen().(BlockStmt).getStmt(0).(IfStmt).getElse().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vc_108
		and target_73.getElse().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=v__res_117
		and target_73.getElse().(ExprStmt).getExpr().(AssignExpr).getRValue().(ArrayExpr).getArrayBase().(PointerDereferenceExpr).getOperand().(FunctionCall).getTarget().hasName("__ctype_tolower_loc")
		and target_73.getElse().(ExprStmt).getExpr().(AssignExpr).getRValue().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vc_108
}

*/
/*predicate func_74(Variable vc_108, Variable v__res_117, Variable v__c_117, IfStmt target_74) {
		target_74.getCondition().(FunctionCall).getTarget().hasName("__builtin_constant_p")
		and target_74.getCondition().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vc_108
		and target_74.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=v__res_117
		and target_74.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(ConditionalExpr).getThen().(VariableAccess).getTarget()=v__c_117
		and target_74.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(ConditionalExpr).getElse().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=v__c_117
		and target_74.getElse().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=v__res_117
		and target_74.getElse().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("tolower")
		and target_74.getElse().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vc_108
}

*/
/*predicate func_76(Variable v__res_117, Variable v__c_117, ExprStmt target_76) {
		target_76.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=v__res_117
		and target_76.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=v__c_117
		and target_76.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(UnaryMinusExpr).getValue()="-128"
		and target_76.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=v__c_117
		and target_76.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="255"
		and target_76.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getThen().(VariableAccess).getTarget()=v__c_117
		and target_76.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getElse().(ArrayExpr).getArrayBase().(PointerDereferenceExpr).getOperand().(FunctionCall).getTarget().hasName("__ctype_tolower_loc")
		and target_76.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getElse().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=v__c_117
}

*/
/*predicate func_77(Variable v__res_117, ExprStmt target_77) {
		target_77.getExpr().(VariableAccess).getTarget()=v__res_117
}

*/
/*predicate func_78(Parameter vpattern_56, ExprStmt target_78) {
		target_78.getExpr().(AssignPointerAddExpr).getLValue().(VariableAccess).getTarget()=vpattern_56
		and target_78.getExpr().(AssignPointerAddExpr).getRValue().(Literal).getValue()="2"
}

*/
/*predicate func_79(Parameter vpatternLen_56, ExprStmt target_79) {
		target_79.getExpr().(AssignSubExpr).getLValue().(VariableAccess).getTarget()=vpatternLen_56
		and target_79.getExpr().(AssignSubExpr).getRValue().(Literal).getValue()="2"
}

*/
/*predicate func_80(Variable vmatch_83, Variable vstart_106, Variable vend_107, Variable vc_108, IfStmt target_80) {
		target_80.getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vc_108
		and target_80.getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vstart_106
		and target_80.getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vc_108
		and target_80.getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vend_107
		and target_80.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vmatch_83
		and target_80.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="1"
}

*/
/*predicate func_81(Parameter vpattern_56, Parameter vstring_57, Parameter vnocase_57, Variable vmatch_83, IfStmt target_81) {
		target_81.getCondition().(NotExpr).getOperand().(VariableAccess).getTarget()=vnocase_57
		and target_81.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vpattern_56
		and target_81.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_81.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vstring_57
		and target_81.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_81.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vmatch_83
		and target_81.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="1"
		and target_81.getElse().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vmatch_83
		and target_81.getElse().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="1"
}

*/
/*predicate func_82(Parameter vpattern_56, Parameter vstring_57, Variable vmatch_83, IfStmt target_82) {
		target_82.getCondition().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vpattern_56
		and target_82.getCondition().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_82.getCondition().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vstring_57
		and target_82.getCondition().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_82.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vmatch_83
		and target_82.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="1"
}

*/
/*predicate func_83(Variable vmatch_83, Variable v__res_128, Variable v__res_1_128, IfStmt target_83) {
		target_83.getCondition().(EqualityOperation).getAnOperand().(StmtExpr).getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(RelationalOperation).getValue()="1"
		and target_83.getCondition().(EqualityOperation).getAnOperand().(StmtExpr).getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(VariableAccess).getTarget()=v__res_128
		and target_83.getCondition().(EqualityOperation).getAnOperand().(StmtExpr).getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(RelationalOperation).getValue()="1"
		and target_83.getCondition().(EqualityOperation).getAnOperand().(StmtExpr).getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(VariableAccess).getTarget()=v__res_1_128
		and target_83.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vmatch_83
		and target_83.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="1"
}

*/
/*predicate func_85(Parameter vpattern_56, Variable v__res_128, IfStmt target_85) {
		target_85.getCondition().(RelationalOperation).getValue()="1"
		and target_85.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(FunctionCall).getTarget().hasName("__builtin_constant_p")
		and target_85.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(FunctionCall).getArgument(0).(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vpattern_56
		and target_85.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(FunctionCall).getArgument(0).(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_85.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=v__res_128
		and target_85.getThen().(BlockStmt).getStmt(0).(IfStmt).getElse().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=v__res_128
		and target_85.getThen().(BlockStmt).getStmt(0).(IfStmt).getElse().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("tolower")
		and target_85.getElse().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=v__res_128
		and target_85.getElse().(ExprStmt).getExpr().(AssignExpr).getRValue().(ArrayExpr).getArrayBase().(PointerDereferenceExpr).getOperand().(FunctionCall).getTarget().hasName("__ctype_tolower_loc")
		and target_85.getElse().(ExprStmt).getExpr().(AssignExpr).getRValue().(ArrayExpr).getArrayOffset().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vpattern_56
		and target_85.getElse().(ExprStmt).getExpr().(AssignExpr).getRValue().(ArrayExpr).getArrayOffset().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
}

*/
/*predicate func_86(Parameter vpattern_56, Variable v__res_128, Variable v__c_128, IfStmt target_86) {
		target_86.getCondition().(FunctionCall).getTarget().hasName("__builtin_constant_p")
		and target_86.getCondition().(FunctionCall).getArgument(0).(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vpattern_56
		and target_86.getCondition().(FunctionCall).getArgument(0).(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_86.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=v__res_128
		and target_86.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(ConditionalExpr).getThen().(VariableAccess).getTarget()=v__c_128
		and target_86.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(ConditionalExpr).getElse().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=v__c_128
		and target_86.getElse().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=v__res_128
		and target_86.getElse().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("tolower")
		and target_86.getElse().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vpattern_56
		and target_86.getElse().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
}

*/
/*predicate func_88(Variable v__res_128, Variable v__c_128, ExprStmt target_88) {
		target_88.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=v__res_128
		and target_88.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=v__c_128
		and target_88.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(UnaryMinusExpr).getValue()="-128"
		and target_88.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=v__c_128
		and target_88.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="255"
		and target_88.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getThen().(VariableAccess).getTarget()=v__c_128
		and target_88.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getElse().(ArrayExpr).getArrayBase().(PointerDereferenceExpr).getOperand().(FunctionCall).getTarget().hasName("__ctype_tolower_loc")
		and target_88.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getElse().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=v__c_128
}

*/
/*predicate func_89(Variable v__res_128, ExprStmt target_89) {
		target_89.getExpr().(VariableAccess).getTarget()=v__res_128
}

*/
/*predicate func_91(Parameter vstring_57, Variable v__res_1_128, IfStmt target_91) {
		target_91.getCondition().(RelationalOperation).getValue()="1"
		and target_91.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(FunctionCall).getTarget().hasName("__builtin_constant_p")
		and target_91.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(FunctionCall).getArgument(0).(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vstring_57
		and target_91.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(FunctionCall).getArgument(0).(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_91.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=v__res_1_128
		and target_91.getThen().(BlockStmt).getStmt(0).(IfStmt).getElse().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=v__res_1_128
		and target_91.getThen().(BlockStmt).getStmt(0).(IfStmt).getElse().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("tolower")
		and target_91.getElse().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=v__res_1_128
		and target_91.getElse().(ExprStmt).getExpr().(AssignExpr).getRValue().(ArrayExpr).getArrayBase().(PointerDereferenceExpr).getOperand().(FunctionCall).getTarget().hasName("__ctype_tolower_loc")
		and target_91.getElse().(ExprStmt).getExpr().(AssignExpr).getRValue().(ArrayExpr).getArrayOffset().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vstring_57
		and target_91.getElse().(ExprStmt).getExpr().(AssignExpr).getRValue().(ArrayExpr).getArrayOffset().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
}

*/
/*predicate func_92(Parameter vstring_57, Variable v__res_1_128, Variable v__c_1_128, IfStmt target_92) {
		target_92.getCondition().(FunctionCall).getTarget().hasName("__builtin_constant_p")
		and target_92.getCondition().(FunctionCall).getArgument(0).(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vstring_57
		and target_92.getCondition().(FunctionCall).getArgument(0).(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_92.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=v__res_1_128
		and target_92.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(ConditionalExpr).getThen().(VariableAccess).getTarget()=v__c_1_128
		and target_92.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(ConditionalExpr).getElse().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=v__c_1_128
		and target_92.getElse().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=v__res_1_128
		and target_92.getElse().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("tolower")
		and target_92.getElse().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vstring_57
		and target_92.getElse().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
}

*/
/*predicate func_94(Variable v__res_1_128, Variable v__c_1_128, ExprStmt target_94) {
		target_94.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=v__res_1_128
		and target_94.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=v__c_1_128
		and target_94.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(UnaryMinusExpr).getValue()="-128"
		and target_94.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=v__c_1_128
		and target_94.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="255"
		and target_94.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getThen().(VariableAccess).getTarget()=v__c_1_128
		and target_94.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getElse().(ArrayExpr).getArrayBase().(PointerDereferenceExpr).getOperand().(FunctionCall).getTarget().hasName("__ctype_tolower_loc")
		and target_94.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getElse().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=v__c_1_128
}

*/
/*predicate func_95(Variable v__res_1_128, ExprStmt target_95) {
		target_95.getExpr().(VariableAccess).getTarget()=v__res_1_128
}

*/
/*predicate func_96(Parameter vpattern_56, ExprStmt target_96) {
		target_96.getExpr().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vpattern_56
}

*/
/*predicate func_97(Parameter vpatternLen_56, ExprStmt target_97) {
		target_97.getExpr().(PostfixDecrExpr).getOperand().(VariableAccess).getTarget()=vpatternLen_56
}

*/
/*predicate func_99(Variable vnot_83, Variable vmatch_83, IfStmt target_99) {
		target_99.getCondition().(VariableAccess).getTarget()=vnot_83
		and target_99.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vmatch_83
		and target_99.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(NotExpr).getOperand().(VariableAccess).getTarget()=vmatch_83
}

*/
/*predicate func_100(Variable vmatch_83, IfStmt target_100) {
		target_100.getCondition().(NotExpr).getOperand().(VariableAccess).getTarget()=vmatch_83
		and target_100.getThen().(ReturnStmt).getExpr().(Literal).getValue()="0"
}

*/
/*predicate func_101(Parameter vstring_57, ExprStmt target_101) {
		target_101.getExpr().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vstring_57
}

*/
/*predicate func_102(Parameter vstringLen_57, ExprStmt target_102) {
		target_102.getExpr().(PostfixDecrExpr).getOperand().(VariableAccess).getTarget()=vstringLen_57
}

*/
/*predicate func_104(Function func, SwitchCase target_104) {
		target_104.getExpr().(CharLiteral).getValue()="92"
		and target_104.getEnclosingFunction() = func
}

*/
/*predicate func_105(Parameter vpattern_56, Parameter vpatternLen_56, IfStmt target_105) {
		target_105.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vpatternLen_56
		and target_105.getCondition().(RelationalOperation).getLesserOperand().(Literal).getValue()="2"
		and target_105.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vpattern_56
		and target_105.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(PostfixDecrExpr).getOperand().(VariableAccess).getTarget()=vpatternLen_56
}

*/
/*predicate func_106(Parameter vpattern_56, ExprStmt target_106) {
		target_106.getExpr().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vpattern_56
}

*/
/*predicate func_107(Parameter vpatternLen_56, ExprStmt target_107) {
		target_107.getExpr().(PostfixDecrExpr).getOperand().(VariableAccess).getTarget()=vpatternLen_56
}

*/
/*predicate func_108(Function func, SwitchCase target_108) {
		target_108.toString() = "default: "
		and target_108.getEnclosingFunction() = func
}

*/
/*predicate func_109(Parameter vpattern_56, Parameter vstring_57, Parameter vnocase_57, IfStmt target_109) {
		target_109.getCondition().(NotExpr).getOperand().(VariableAccess).getTarget()=vnocase_57
		and target_109.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vpattern_56
		and target_109.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_109.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vstring_57
		and target_109.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_109.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(ReturnStmt).getExpr().(Literal).getValue()="0"
		and target_109.getElse().(BlockStmt).getStmt(0).(IfStmt).getThen().(ReturnStmt).getExpr().(Literal).getValue()="0"
}

*/
/*predicate func_110(Parameter vpattern_56, Parameter vstring_57, IfStmt target_110) {
		target_110.getCondition().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vpattern_56
		and target_110.getCondition().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_110.getCondition().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vstring_57
		and target_110.getCondition().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_110.getThen().(ReturnStmt).getExpr().(Literal).getValue()="0"
}

*/
/*predicate func_111(Variable v__res_154, Variable v__res_1_154, IfStmt target_111) {
		target_111.getCondition().(EqualityOperation).getAnOperand().(StmtExpr).getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(RelationalOperation).getValue()="1"
		and target_111.getCondition().(EqualityOperation).getAnOperand().(StmtExpr).getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(VariableAccess).getTarget()=v__res_154
		and target_111.getCondition().(EqualityOperation).getAnOperand().(StmtExpr).getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(RelationalOperation).getValue()="1"
		and target_111.getCondition().(EqualityOperation).getAnOperand().(StmtExpr).getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(VariableAccess).getTarget()=v__res_1_154
		and target_111.getThen().(ReturnStmt).getExpr().(Literal).getValue()="0"
}

*/
/*predicate func_113(Parameter vpattern_56, Variable v__res_154, IfStmt target_113) {
		target_113.getCondition().(RelationalOperation).getValue()="1"
		and target_113.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(FunctionCall).getTarget().hasName("__builtin_constant_p")
		and target_113.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(FunctionCall).getArgument(0).(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vpattern_56
		and target_113.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(FunctionCall).getArgument(0).(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_113.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=v__res_154
		and target_113.getThen().(BlockStmt).getStmt(0).(IfStmt).getElse().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=v__res_154
		and target_113.getThen().(BlockStmt).getStmt(0).(IfStmt).getElse().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("tolower")
		and target_113.getElse().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=v__res_154
		and target_113.getElse().(ExprStmt).getExpr().(AssignExpr).getRValue().(ArrayExpr).getArrayBase().(PointerDereferenceExpr).getOperand().(FunctionCall).getTarget().hasName("__ctype_tolower_loc")
		and target_113.getElse().(ExprStmt).getExpr().(AssignExpr).getRValue().(ArrayExpr).getArrayOffset().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vpattern_56
		and target_113.getElse().(ExprStmt).getExpr().(AssignExpr).getRValue().(ArrayExpr).getArrayOffset().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
}

*/
/*predicate func_114(Parameter vpattern_56, Variable v__res_154, Variable v__c_154, IfStmt target_114) {
		target_114.getCondition().(FunctionCall).getTarget().hasName("__builtin_constant_p")
		and target_114.getCondition().(FunctionCall).getArgument(0).(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vpattern_56
		and target_114.getCondition().(FunctionCall).getArgument(0).(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_114.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=v__res_154
		and target_114.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(ConditionalExpr).getThen().(VariableAccess).getTarget()=v__c_154
		and target_114.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(ConditionalExpr).getElse().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=v__c_154
		and target_114.getElse().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=v__res_154
		and target_114.getElse().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("tolower")
		and target_114.getElse().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vpattern_56
		and target_114.getElse().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
}

*/
/*predicate func_116(Variable v__res_154, Variable v__c_154, ExprStmt target_116) {
		target_116.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=v__res_154
		and target_116.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=v__c_154
		and target_116.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(UnaryMinusExpr).getValue()="-128"
		and target_116.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=v__c_154
		and target_116.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="255"
		and target_116.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getThen().(VariableAccess).getTarget()=v__c_154
		and target_116.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getElse().(ArrayExpr).getArrayBase().(PointerDereferenceExpr).getOperand().(FunctionCall).getTarget().hasName("__ctype_tolower_loc")
		and target_116.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getElse().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=v__c_154
}

*/
/*predicate func_117(Variable v__res_154, ExprStmt target_117) {
		target_117.getExpr().(VariableAccess).getTarget()=v__res_154
}

*/
/*predicate func_119(Parameter vstring_57, Variable v__res_1_154, IfStmt target_119) {
		target_119.getCondition().(RelationalOperation).getValue()="1"
		and target_119.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(FunctionCall).getTarget().hasName("__builtin_constant_p")
		and target_119.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(FunctionCall).getArgument(0).(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vstring_57
		and target_119.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(FunctionCall).getArgument(0).(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_119.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=v__res_1_154
		and target_119.getThen().(BlockStmt).getStmt(0).(IfStmt).getElse().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=v__res_1_154
		and target_119.getThen().(BlockStmt).getStmt(0).(IfStmt).getElse().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("tolower")
		and target_119.getElse().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=v__res_1_154
		and target_119.getElse().(ExprStmt).getExpr().(AssignExpr).getRValue().(ArrayExpr).getArrayBase().(PointerDereferenceExpr).getOperand().(FunctionCall).getTarget().hasName("__ctype_tolower_loc")
		and target_119.getElse().(ExprStmt).getExpr().(AssignExpr).getRValue().(ArrayExpr).getArrayOffset().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vstring_57
		and target_119.getElse().(ExprStmt).getExpr().(AssignExpr).getRValue().(ArrayExpr).getArrayOffset().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
}

*/
/*predicate func_120(Parameter vstring_57, Variable v__res_1_154, Variable v__c_1_154, IfStmt target_120) {
		target_120.getCondition().(FunctionCall).getTarget().hasName("__builtin_constant_p")
		and target_120.getCondition().(FunctionCall).getArgument(0).(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vstring_57
		and target_120.getCondition().(FunctionCall).getArgument(0).(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_120.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=v__res_1_154
		and target_120.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(ConditionalExpr).getThen().(VariableAccess).getTarget()=v__c_1_154
		and target_120.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(ConditionalExpr).getElse().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=v__c_1_154
		and target_120.getElse().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=v__res_1_154
		and target_120.getElse().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("tolower")
		and target_120.getElse().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vstring_57
		and target_120.getElse().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
}

*/
/*predicate func_122(Variable v__res_1_154, Variable v__c_1_154, ExprStmt target_122) {
		target_122.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=v__res_1_154
		and target_122.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=v__c_1_154
		and target_122.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(UnaryMinusExpr).getValue()="-128"
		and target_122.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=v__c_1_154
		and target_122.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="255"
		and target_122.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getThen().(VariableAccess).getTarget()=v__c_1_154
		and target_122.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getElse().(ArrayExpr).getArrayBase().(PointerDereferenceExpr).getOperand().(FunctionCall).getTarget().hasName("__ctype_tolower_loc")
		and target_122.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getElse().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=v__c_1_154
}

*/
/*predicate func_123(Variable v__res_1_154, ExprStmt target_123) {
		target_123.getExpr().(VariableAccess).getTarget()=v__res_1_154
}

*/
/*predicate func_124(Parameter vstring_57, ExprStmt target_124) {
		target_124.getExpr().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vstring_57
}

*/
/*predicate func_125(Parameter vstringLen_57, ExprStmt target_125) {
		target_125.getExpr().(PostfixDecrExpr).getOperand().(VariableAccess).getTarget()=vstringLen_57
}

*/
/*predicate func_128(Parameter vpattern_56, ExprStmt target_128) {
		target_128.getExpr().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vpattern_56
}

*/
/*predicate func_129(Parameter vpatternLen_56, ExprStmt target_129) {
		target_129.getExpr().(PostfixDecrExpr).getOperand().(VariableAccess).getTarget()=vpatternLen_56
}

*/
/*predicate func_130(Parameter vpattern_56, Parameter vpatternLen_56, Parameter vstringLen_57, IfStmt target_130) {
		target_130.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vstringLen_57
		and target_130.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_130.getThen().(BlockStmt).getStmt(0).(WhileStmt).getCondition().(EqualityOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vpattern_56
		and target_130.getThen().(BlockStmt).getStmt(0).(WhileStmt).getCondition().(EqualityOperation).getAnOperand().(CharLiteral).getValue()="42"
		and target_130.getThen().(BlockStmt).getStmt(0).(WhileStmt).getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vpattern_56
		and target_130.getThen().(BlockStmt).getStmt(0).(WhileStmt).getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(PostfixDecrExpr).getOperand().(VariableAccess).getTarget()=vpatternLen_56
}

*/
/*predicate func_131(Parameter vpattern_56, Parameter vpatternLen_56, WhileStmt target_131) {
		target_131.getCondition().(EqualityOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vpattern_56
		and target_131.getCondition().(EqualityOperation).getAnOperand().(CharLiteral).getValue()="42"
		and target_131.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vpattern_56
		and target_131.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(PostfixDecrExpr).getOperand().(VariableAccess).getTarget()=vpatternLen_56
}

*/
/*predicate func_132(Parameter vpattern_56, ExprStmt target_132) {
		target_132.getExpr().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vpattern_56
}

*/
/*predicate func_133(Parameter vpatternLen_56, ExprStmt target_133) {
		target_133.getExpr().(PostfixDecrExpr).getOperand().(VariableAccess).getTarget()=vpatternLen_56
}

*/
predicate func_136(Parameter vpatternLen_56, Parameter vstringLen_57, IfStmt target_136) {
		target_136.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vpatternLen_56
		and target_136.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_136.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vstringLen_57
		and target_136.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_136.getThen().(ReturnStmt).getExpr().(Literal).getValue()="1"
}

predicate func_137(Function func, ReturnStmt target_137) {
		target_137.getExpr().(Literal).getValue()="0"
		and target_137.getEnclosingFunction() = func
}

predicate func_138(ReturnStmt target_138) {
		target_138.getExpr() instanceof Literal
}

predicate func_139(Parameter vpattern_56, ArrayExpr target_139) {
		target_139.getArrayBase().(VariableAccess).getTarget()=vpattern_56
		and target_139.getArrayOffset() instanceof Literal
}

predicate func_141(Parameter vpattern_56, PointerArithmeticOperation target_141) {
		target_141.getAnOperand().(VariableAccess).getTarget()=vpattern_56
		and target_141.getAnOperand() instanceof Literal
}

predicate func_142(Parameter vpatternLen_56, LogicalAndExpr target_142) {
		target_142.getAnOperand().(VariableAccess).getTarget()=vpatternLen_56
		and target_142.getAnOperand() instanceof EqualityOperation
}

predicate func_143(Parameter vpatternLen_56, EqualityOperation target_143) {
		target_143.getAnOperand().(VariableAccess).getTarget()=vpatternLen_56
		and target_143.getAnOperand() instanceof Literal
}

from Function func, Parameter vpattern_56, Parameter vpatternLen_56, Parameter vstring_57, Parameter vstringLen_57, Parameter vnocase_57, Variable vnot_83, Variable vmatch_83, Variable vstart_106, Variable vend_107, Variable vc_108, Variable vt_110, Variable v__res_115, Variable v__c_115, Variable v__res_116, Variable v__c_116, Variable v__res_117, Variable v__c_117, Variable v__res_128, Variable v__c_128, Variable v__res_1_128, Variable v__c_1_128, Variable v__res_154, Variable v__c_154, Variable v__res_1_154, Variable v__c_1_154, VariableAccess target_0, FunctionCall target_1, Initializer target_2, VariableAccess target_5, VariableAccess target_6, WhileStmt target_7, ExprStmt target_11, ExprStmt target_26, ExprStmt target_27, ExprStmt target_31, ExprStmt target_32, IfStmt target_136, ReturnStmt target_137, ReturnStmt target_138, ArrayExpr target_139, PointerArithmeticOperation target_141, LogicalAndExpr target_142, EqualityOperation target_143
where
func_0(vpatternLen_56, target_0)
and func_1(vpattern_56, vpatternLen_56, vstring_57, vstringLen_57, vnocase_57, target_138, target_1)
and func_2(vpattern_56, target_2)
and not func_3(vpattern_56, vpatternLen_56, vstring_57, vstringLen_57, vnocase_57, target_138)
and func_5(vpatternLen_56, vstringLen_57, target_5)
and func_6(vpattern_56, target_6)
and func_7(vpattern_56, vpatternLen_56, vstringLen_57, target_7)
and func_11(vpattern_56, target_141, target_11)
and func_26(vstring_57, target_26)
and func_27(vstringLen_57, target_27)
and func_31(vpattern_56, target_31)
and func_32(vpatternLen_56, target_32)
and func_136(vpatternLen_56, vstringLen_57, target_136)
and func_137(func, target_137)
and func_138(target_138)
and func_139(vpattern_56, target_139)
and func_141(vpattern_56, target_141)
and func_142(vpatternLen_56, target_142)
and func_143(vpatternLen_56, target_143)
and vpattern_56.getType().hasName("const char *")
and vpatternLen_56.getType().hasName("int")
and vstring_57.getType().hasName("const char *")
and vstringLen_57.getType().hasName("int")
and vnocase_57.getType().hasName("int")
and vnot_83.getType().hasName("int")
and vmatch_83.getType().hasName("int")
and vstart_106.getType().hasName("int")
and vend_107.getType().hasName("int")
and vc_108.getType().hasName("int")
and vt_110.getType().hasName("int")
and v__res_115.getType().hasName("int")
and v__c_115.getType().hasName("int")
and v__res_116.getType().hasName("int")
and v__c_116.getType().hasName("int")
and v__res_117.getType().hasName("int")
and v__c_117.getType().hasName("int")
and v__res_128.getType().hasName("int")
and v__c_128.getType().hasName("int")
and v__res_1_128.getType().hasName("int")
and v__c_1_128.getType().hasName("int")
and v__res_154.getType().hasName("int")
and v__c_154.getType().hasName("int")
and v__res_1_154.getType().hasName("int")
and v__c_1_154.getType().hasName("int")
and vpattern_56.getFunction() = func
and vpatternLen_56.getFunction() = func
and vstring_57.getFunction() = func
and vstringLen_57.getFunction() = func
and vnocase_57.getFunction() = func
and vnot_83.(LocalVariable).getFunction() = func
and vmatch_83.(LocalVariable).getFunction() = func
and vstart_106.(LocalVariable).getFunction() = func
and vend_107.(LocalVariable).getFunction() = func
and vc_108.(LocalVariable).getFunction() = func
and vt_110.(LocalVariable).getFunction() = func
and v__res_115.(LocalVariable).getFunction() = func
and v__c_115.(LocalVariable).getFunction() = func
and v__res_116.(LocalVariable).getFunction() = func
and v__c_116.(LocalVariable).getFunction() = func
and v__res_117.(LocalVariable).getFunction() = func
and v__c_117.(LocalVariable).getFunction() = func
and v__res_128.(LocalVariable).getFunction() = func
and v__c_128.(LocalVariable).getFunction() = func
and v__res_1_128.(LocalVariable).getFunction() = func
and v__c_1_128.(LocalVariable).getFunction() = func
and v__res_154.(LocalVariable).getFunction() = func
and v__c_154.(LocalVariable).getFunction() = func
and v__res_1_154.(LocalVariable).getFunction() = func
and v__c_1_154.(LocalVariable).getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
