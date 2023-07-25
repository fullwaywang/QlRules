/**
 * @name openssh-8976f1c4b2721c26e878151f52bdf346dfe2d54c-refresh_progress_meter
 * @id cpp/openssh/8976f1c4b2721c26e878151f52bdf346dfe2d54c/refresh-progress-meter
 * @description openssh-8976f1c4b2721c26e878151f52bdf346dfe2d54c-progressmeter.c-refresh_progress_meter CVE-2019-6109
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func, Literal target_0) {
		target_0.getValue()="35"
		and not target_0.getValue()="36"
		and target_0.getEnclosingFunction() = func
}

predicate func_1(Variable vlen_129, RelationalOperation target_22, VariableAccess target_1) {
		target_1.getTarget()=vlen_129
		and target_1.getParent().(AssignExpr).getLValue() = target_1
		and target_1.getParent().(AssignExpr).getRValue() instanceof FunctionCall
		and target_1.getLocation().isBefore(target_22.getLesserOperand().(VariableAccess).getLocation())
}

predicate func_2(Function func, StringLiteral target_2) {
		target_2.getValue()="\r%s"
		and not target_2.getValue()="%*s"
		and target_2.getEnclosingFunction() = func
}

predicate func_3(Function func, Literal target_3) {
		target_3.getValue()="0"
		and not target_3.getValue()="1"
		and target_3.getParent().(AssignExpr).getParent().(ExprStmt).getExpr() instanceof AssignExpr
		and target_3.getEnclosingFunction() = func
}

predicate func_4(Function func, CharLiteral target_4) {
		target_4.getValue()="32"
		and not target_4.getValue()="13"
		and target_4.getEnclosingFunction() = func
}

predicate func_5(BlockStmt target_30, Function func) {
	exists(LogicalOrExpr target_5 |
		target_5.getAnOperand().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(VariableAccess).getType().hasName("sig_atomic_t")
		and target_5.getAnOperand().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(VariableAccess).getType().hasName("sig_atomic_t")
		and target_5.getAnOperand().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("can_output")
		and target_5.getParent().(IfStmt).getThen()=target_30
		and target_5.getEnclosingFunction() = func)
}

predicate func_6(RelationalOperation target_12, Function func) {
	exists(ReturnStmt target_6 |
		target_6.toString() = "return ..."
		and target_6.getParent().(IfStmt).getCondition()=target_12
		and target_6.getEnclosingFunction() = func)
}

predicate func_7(Function func) {
	exists(AssignExpr target_7 |
		target_7.getLValue().(VariableAccess).getType().hasName("volatile sig_atomic_t")
		and target_7.getRValue().(Literal).getValue()="0"
		and target_7.getEnclosingFunction() = func)
}

predicate func_9(Function func) {
	exists(FunctionCall target_9 |
		target_9.getTarget().hasName("setscreensize")
		and target_9.getEnclosingFunction() = func)
}

predicate func_10(Function func) {
	exists(AssignExpr target_10 |
		target_10.getLValue().(VariableAccess).getType().hasName("volatile sig_atomic_t")
		and target_10.getRValue().(Literal).getValue()="0"
		and target_10.getEnclosingFunction() = func)
}

predicate func_11(Variable vbuf_122, Variable vfile_len_130, Variable vfile, ExprStmt target_31, ExprStmt target_32, RelationalOperation target_12, RelationalOperation target_24) {
	exists(FunctionCall target_11 |
		target_11.getTarget().hasName("snmprintf")
		and target_11.getArgument(0).(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vbuf_122
		and target_11.getArgument(0).(PointerArithmeticOperation).getAnOperand() instanceof Literal
		and target_11.getArgument(1).(SubExpr).getValue()="512"
		and target_11.getArgument(2).(AddressOfExpr).getOperand().(VariableAccess).getType().hasName("int")
		and target_11.getArgument(3).(StringLiteral).getValue()="%*s"
		and target_11.getArgument(4).(MulExpr).getLeftOperand().(VariableAccess).getTarget()=vfile_len_130
		and target_11.getArgument(4).(MulExpr).getRightOperand().(UnaryMinusExpr).getValue()="-1"
		and target_11.getArgument(5).(VariableAccess).getTarget()=vfile
		and target_31.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getLocation().isBefore(target_11.getArgument(0).(PointerArithmeticOperation).getAnOperand().(VariableAccess).getLocation())
		and target_11.getArgument(0).(PointerArithmeticOperation).getAnOperand().(VariableAccess).getLocation().isBefore(target_32.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getLocation())
		and target_12.getGreaterOperand().(VariableAccess).getLocation().isBefore(target_11.getArgument(4).(MulExpr).getLeftOperand().(VariableAccess).getLocation())
		and target_11.getArgument(4).(MulExpr).getLeftOperand().(VariableAccess).getLocation().isBefore(target_24.getLesserOperand().(AddExpr).getAnOperand().(VariableAccess).getLocation()))
}

predicate func_12(Variable vfile_len_130, BlockStmt target_30, RelationalOperation target_12) {
		 (target_12 instanceof GTExpr or target_12 instanceof LTExpr)
		and target_12.getGreaterOperand().(VariableAccess).getTarget()=vfile_len_130
		and target_12.getLesserOperand().(Literal).getValue()="0"
		and target_12.getParent().(IfStmt).getThen()=target_30
}

predicate func_13(Variable vfile_len_130, VariableAccess target_13) {
		target_13.getTarget()=vfile_len_130
}

predicate func_16(Variable vbuf_122, VariableAccess target_16) {
		target_16.getTarget()=vbuf_122
		and target_16.getParent().(FunctionCall).getParent().(AssignExpr).getRValue() instanceof FunctionCall
}

predicate func_17(Variable vfile, VariableAccess target_17) {
		target_17.getTarget()=vfile
		and target_17.getParent().(FunctionCall).getParent().(AssignExpr).getRValue() instanceof FunctionCall
}

predicate func_19(Variable vbuf_122, Variable vfile_len_130, VariableAccess target_19) {
		target_19.getTarget()=vbuf_122
		and target_19.getParent().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vfile_len_130
}

predicate func_20(Function func, DeclStmt target_20) {
		func.getEntryPoint().(BlockStmt).getAStmt()=target_20
}

predicate func_21(Variable vbuf_122, Variable vlen_129, Variable vfile_len_130, Variable vfile, AssignExpr target_21) {
		target_21.getLValue().(VariableAccess).getTarget()=vlen_129
		and target_21.getRValue().(FunctionCall).getTarget().hasName("snprintf")
		and target_21.getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vbuf_122
		and target_21.getRValue().(FunctionCall).getArgument(1).(AddExpr).getAnOperand().(VariableAccess).getTarget()=vfile_len_130
		and target_21.getRValue().(FunctionCall).getArgument(1).(AddExpr).getAnOperand() instanceof Literal
		and target_21.getRValue().(FunctionCall).getArgument(2) instanceof StringLiteral
		and target_21.getRValue().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vfile
}

predicate func_22(Variable vlen_129, ExprStmt target_33, RelationalOperation target_22) {
		 (target_22 instanceof GTExpr or target_22 instanceof LTExpr)
		and target_22.getLesserOperand().(VariableAccess).getTarget()=vlen_129
		and target_22.getGreaterOperand() instanceof Literal
		and target_22.getParent().(IfStmt).getThen()=target_33
}

predicate func_23(Variable vlen_129, AssignExpr target_23) {
		target_23.getLValue().(VariableAccess).getTarget()=vlen_129
		and target_23.getRValue() instanceof Literal
}

predicate func_24(Variable vlen_129, Variable vfile_len_130, ExprStmt target_34, RelationalOperation target_24) {
		 (target_24 instanceof GEExpr or target_24 instanceof LEExpr)
		and target_24.getGreaterOperand().(VariableAccess).getTarget()=vlen_129
		and target_24.getLesserOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vfile_len_130
		and target_24.getLesserOperand().(AddExpr).getAnOperand() instanceof Literal
		and target_24.getParent().(IfStmt).getThen()=target_34
}

predicate func_25(Variable vlen_129, Variable vfile_len_130, AssignExpr target_25) {
		target_25.getLValue().(VariableAccess).getTarget()=vlen_129
		and target_25.getRValue().(VariableAccess).getTarget()=vfile_len_130
}

predicate func_26(Variable vbuf_122, Variable vi_129, Variable vlen_129, Variable vfile_len_130, RelationalOperation target_12, ForStmt target_26) {
		target_26.getInitialization().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vi_129
		and target_26.getInitialization().(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vlen_129
		and target_26.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vi_129
		and target_26.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vfile_len_130
		and target_26.getUpdate().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vi_129
		and target_26.getStmt().(ExprStmt).getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vbuf_122
		and target_26.getStmt().(ExprStmt).getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_129
		and target_26.getStmt().(ExprStmt).getExpr().(AssignExpr).getRValue() instanceof CharLiteral
		and target_26.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_12
}

/*predicate func_27(Variable vi_129, Variable vlen_129, AssignExpr target_27) {
		target_27.getLValue().(VariableAccess).getTarget()=vi_129
		and target_27.getRValue().(VariableAccess).getTarget()=vlen_129
}

*/
/*predicate func_28(Variable vbuf_122, Variable vi_129, PostfixIncrExpr target_37, VariableAccess target_28) {
		target_28.getTarget()=vi_129
		and target_28.getParent().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vbuf_122
		and target_37.getOperand().(VariableAccess).getLocation().isBefore(target_28.getLocation())
}

*/
predicate func_29(Variable vbuf_122, Variable vfile_len_130, AssignExpr target_29) {
		target_29.getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vbuf_122
		and target_29.getLValue().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vfile_len_130
		and target_29.getRValue().(CharLiteral).getValue()="0"
}

predicate func_30(BlockStmt target_30) {
		target_30.getStmt(0).(ExprStmt).getExpr() instanceof AssignExpr
		and target_30.getStmt(1).(IfStmt).getCondition() instanceof RelationalOperation
		and target_30.getStmt(1).(IfStmt).getThen().(ExprStmt).getExpr() instanceof AssignExpr
		and target_30.getStmt(2).(IfStmt).getCondition() instanceof RelationalOperation
		and target_30.getStmt(2).(IfStmt).getThen().(ExprStmt).getExpr() instanceof AssignExpr
}

predicate func_31(Variable vbuf_122, ExprStmt target_31) {
		target_31.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vbuf_122
		and target_31.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_31.getExpr().(AssignExpr).getRValue().(CharLiteral).getValue()="0"
}

predicate func_32(Variable vbuf_122, Variable vi_129, ExprStmt target_32) {
		target_32.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vbuf_122
		and target_32.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_129
		and target_32.getExpr().(AssignExpr).getRValue() instanceof CharLiteral
}

predicate func_33(ExprStmt target_33) {
		target_33.getExpr() instanceof AssignExpr
}

predicate func_34(ExprStmt target_34) {
		target_34.getExpr() instanceof AssignExpr
}

predicate func_37(Variable vi_129, PostfixIncrExpr target_37) {
		target_37.getOperand().(VariableAccess).getTarget()=vi_129
}

from Function func, Variable vbuf_122, Variable vi_129, Variable vlen_129, Variable vfile_len_130, Variable vfile, Literal target_0, VariableAccess target_1, StringLiteral target_2, Literal target_3, CharLiteral target_4, RelationalOperation target_12, VariableAccess target_13, VariableAccess target_16, VariableAccess target_17, VariableAccess target_19, DeclStmt target_20, AssignExpr target_21, RelationalOperation target_22, AssignExpr target_23, RelationalOperation target_24, AssignExpr target_25, ForStmt target_26, AssignExpr target_29, BlockStmt target_30, ExprStmt target_31, ExprStmt target_32, ExprStmt target_33, ExprStmt target_34, PostfixIncrExpr target_37
where
func_0(func, target_0)
and func_1(vlen_129, target_22, target_1)
and func_2(func, target_2)
and func_3(func, target_3)
and func_4(func, target_4)
and not func_5(target_30, func)
and not func_6(target_12, func)
and not func_7(func)
and not func_9(func)
and not func_10(func)
and not func_11(vbuf_122, vfile_len_130, vfile, target_31, target_32, target_12, target_24)
and func_12(vfile_len_130, target_30, target_12)
and func_13(vfile_len_130, target_13)
and func_16(vbuf_122, target_16)
and func_17(vfile, target_17)
and func_19(vbuf_122, vfile_len_130, target_19)
and func_20(func, target_20)
and func_21(vbuf_122, vlen_129, vfile_len_130, vfile, target_21)
and func_22(vlen_129, target_33, target_22)
and func_23(vlen_129, target_23)
and func_24(vlen_129, vfile_len_130, target_34, target_24)
and func_25(vlen_129, vfile_len_130, target_25)
and func_26(vbuf_122, vi_129, vlen_129, vfile_len_130, target_12, target_26)
and func_29(vbuf_122, vfile_len_130, target_29)
and func_30(target_30)
and func_31(vbuf_122, target_31)
and func_32(vbuf_122, vi_129, target_32)
and func_33(target_33)
and func_34(target_34)
and func_37(vi_129, target_37)
and vbuf_122.getType().hasName("char[513]")
and vi_129.getType().hasName("int")
and vlen_129.getType().hasName("int")
and vfile_len_130.getType().hasName("int")
and vfile.getType().hasName("const char *")
and vbuf_122.getParentScope+() = func
and vi_129.getParentScope+() = func
and vlen_129.getParentScope+() = func
and vfile_len_130.getParentScope+() = func
and not vfile.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
