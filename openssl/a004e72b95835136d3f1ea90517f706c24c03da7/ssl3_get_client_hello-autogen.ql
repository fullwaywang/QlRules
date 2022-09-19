import cpp

predicate func_2(Variable vj, Variable val, Variable vn, Variable vp, Variable vd) {
	exists(LTExpr target_2 |
		target_2.getType().hasName("int")
		and target_2.getLesserOperand().(PointerDiffExpr).getType().hasName("long")
		and target_2.getLesserOperand().(PointerDiffExpr).getLeftOperand().(PointerAddExpr).getType().hasName("unsigned char *")
		and target_2.getLesserOperand().(PointerDiffExpr).getLeftOperand().(PointerAddExpr).getLeftOperand().(VariableAccess).getTarget()=vd
		and target_2.getLesserOperand().(PointerDiffExpr).getLeftOperand().(PointerAddExpr).getRightOperand().(VariableAccess).getTarget()=vn
		and target_2.getLesserOperand().(PointerDiffExpr).getRightOperand().(VariableAccess).getTarget()=vp
		and target_2.getGreaterOperand().(VariableAccess).getTarget()=vj
		and target_2.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=val
		and target_2.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="50"
		and target_2.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ERR_put_error")
		and target_2.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(Literal).getValue()="20"
		and target_2.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="138"
		and target_2.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(Literal).getValue()="160"
		and target_2.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(StringLiteral).getValue()="s3_srvr.c"
		and target_2.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(4).(Literal).getValue()="1003")
}

predicate func_3(Variable val, Variable vn, Variable vp, Variable vd) {
	exists(LTExpr target_3 |
		target_3.getType().hasName("int")
		and target_3.getLesserOperand().(PointerDiffExpr).getType().hasName("long")
		and target_3.getLesserOperand().(PointerDiffExpr).getLeftOperand().(PointerAddExpr).getType().hasName("unsigned char *")
		and target_3.getLesserOperand().(PointerDiffExpr).getLeftOperand().(PointerAddExpr).getLeftOperand().(VariableAccess).getTarget()=vd
		and target_3.getLesserOperand().(PointerDiffExpr).getLeftOperand().(PointerAddExpr).getRightOperand().(VariableAccess).getTarget()=vn
		and target_3.getLesserOperand().(PointerDiffExpr).getRightOperand().(VariableAccess).getTarget()=vp
		and target_3.getGreaterOperand().(Literal).getValue()="1"
		and target_3.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=val
		and target_3.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="50"
		and target_3.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ERR_put_error")
		and target_3.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(Literal).getValue()="20"
		and target_3.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="138"
		and target_3.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(Literal).getValue()="160"
		and target_3.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(StringLiteral).getValue()="s3_srvr.c"
		and target_3.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(4).(Literal).getValue()="1059")
}

predicate func_4(Variable val, Variable vcookie_len, Variable vn, Variable vp, Variable vd) {
	exists(LTExpr target_4 |
		target_4.getType().hasName("int")
		and target_4.getLesserOperand().(PointerDiffExpr).getType().hasName("long")
		and target_4.getLesserOperand().(PointerDiffExpr).getLeftOperand().(PointerAddExpr).getType().hasName("unsigned char *")
		and target_4.getLesserOperand().(PointerDiffExpr).getLeftOperand().(PointerAddExpr).getLeftOperand().(VariableAccess).getTarget()=vd
		and target_4.getLesserOperand().(PointerDiffExpr).getLeftOperand().(PointerAddExpr).getRightOperand().(VariableAccess).getTarget()=vn
		and target_4.getLesserOperand().(PointerDiffExpr).getRightOperand().(VariableAccess).getTarget()=vp
		and target_4.getGreaterOperand().(VariableAccess).getTarget()=vcookie_len
		and target_4.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=val
		and target_4.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="50"
		and target_4.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ERR_put_error")
		and target_4.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(Literal).getValue()="20"
		and target_4.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="138"
		and target_4.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(Literal).getValue()="160"
		and target_4.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(StringLiteral).getValue()="s3_srvr.c"
		and target_4.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(4).(Literal).getValue()="1066")
}

predicate func_5(Variable val, Variable vn, Variable vp, Variable vd) {
	exists(LTExpr target_5 |
		target_5.getType().hasName("int")
		and target_5.getLesserOperand().(PointerDiffExpr).getType().hasName("long")
		and target_5.getLesserOperand().(PointerDiffExpr).getLeftOperand().(PointerAddExpr).getType().hasName("unsigned char *")
		and target_5.getLesserOperand().(PointerDiffExpr).getLeftOperand().(PointerAddExpr).getLeftOperand().(VariableAccess).getTarget()=vd
		and target_5.getLesserOperand().(PointerDiffExpr).getLeftOperand().(PointerAddExpr).getRightOperand().(VariableAccess).getTarget()=vn
		and target_5.getLesserOperand().(PointerDiffExpr).getRightOperand().(VariableAccess).getTarget()=vp
		and target_5.getGreaterOperand().(Literal).getValue()="2"
		and target_5.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=val
		and target_5.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="50"
		and target_5.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ERR_put_error")
		and target_5.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(Literal).getValue()="20"
		and target_5.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="138"
		and target_5.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(Literal).getValue()="160"
		and target_5.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(StringLiteral).getValue()="s3_srvr.c"
		and target_5.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(4).(Literal).getValue()="1136")
}

predicate func_6(Variable vi, Variable val, Variable vn, Variable vp, Variable vd) {
	exists(LTExpr target_6 |
		target_6.getType().hasName("int")
		and target_6.getLesserOperand().(PointerDiffExpr).getType().hasName("long")
		and target_6.getLesserOperand().(PointerDiffExpr).getLeftOperand().(PointerAddExpr).getType().hasName("unsigned char *")
		and target_6.getLesserOperand().(PointerDiffExpr).getLeftOperand().(PointerAddExpr).getLeftOperand().(VariableAccess).getTarget()=vd
		and target_6.getLesserOperand().(PointerDiffExpr).getLeftOperand().(PointerAddExpr).getRightOperand().(VariableAccess).getTarget()=vn
		and target_6.getLesserOperand().(PointerDiffExpr).getRightOperand().(VariableAccess).getTarget()=vp
		and target_6.getGreaterOperand().(AddExpr).getType().hasName("int")
		and target_6.getGreaterOperand().(AddExpr).getLeftOperand().(VariableAccess).getTarget()=vi
		and target_6.getGreaterOperand().(AddExpr).getRightOperand().(Literal).getValue()="1"
		and target_6.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=val
		and target_6.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="50"
		and target_6.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ERR_put_error")
		and target_6.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(Literal).getValue()="20"
		and target_6.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="138"
		and target_6.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(Literal).getValue()="159"
		and target_6.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(StringLiteral).getValue()="s3_srvr.c"
		and target_6.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(4).(Literal).getValue()="1151")
}

predicate func_7(Variable vi, Variable val, Variable vn, Variable vp, Variable vd) {
	exists(LTExpr target_7 |
		target_7.getType().hasName("int")
		and target_7.getLesserOperand().(PointerDiffExpr).getType().hasName("long")
		and target_7.getLesserOperand().(PointerDiffExpr).getLeftOperand().(PointerAddExpr).getType().hasName("unsigned char *")
		and target_7.getLesserOperand().(PointerDiffExpr).getLeftOperand().(PointerAddExpr).getLeftOperand().(VariableAccess).getTarget()=vd
		and target_7.getLesserOperand().(PointerDiffExpr).getLeftOperand().(PointerAddExpr).getRightOperand().(VariableAccess).getTarget()=vn
		and target_7.getLesserOperand().(PointerDiffExpr).getRightOperand().(VariableAccess).getTarget()=vp
		and target_7.getGreaterOperand().(VariableAccess).getTarget()=vi
		and target_7.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=val
		and target_7.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="50"
		and target_7.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ERR_put_error")
		and target_7.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(Literal).getValue()="20"
		and target_7.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="138"
		and target_7.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(Literal).getValue()="159"
		and target_7.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(StringLiteral).getValue()="s3_srvr.c"
		and target_7.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(4).(Literal).getValue()="1217")
}

predicate func_16(Function func) {
	exists(Literal target_16 |
		target_16.getValue()="1"
		and target_16.getEnclosingFunction() = func)
}

predicate func_24(Function func) {
	exists(Literal target_24 |
		target_24.getValue()="2"
		and target_24.getEnclosingFunction() = func)
}

predicate func_29(Variable vj, Variable val, Variable vp, Function func) {
	exists(GTExpr target_29 |
		target_29.getType().hasName("int")
		and target_29.getGreaterOperand().(PointerAddExpr).getType().hasName("unsigned char *")
		and target_29.getGreaterOperand().(PointerAddExpr).getLeftOperand().(VariableAccess).getTarget()=vp
		and target_29.getGreaterOperand().(PointerAddExpr).getRightOperand().(VariableAccess).getTarget()=vj
		and target_29.getLesserOperand() instanceof PointerAddExpr
		and target_29.getEnclosingFunction() = func
		and target_29.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=val
		and target_29.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="50"
		and target_29.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ERR_put_error")
		and target_29.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(Literal).getValue()="20"
		and target_29.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="138"
		and target_29.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(Literal).getValue()="160"
		and target_29.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(StringLiteral).getValue()="s3_srvr.c"
		and target_29.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(4).(Literal).getValue()="1003")
}

predicate func_30(Variable val, Variable vp, Function func) {
	exists(GTExpr target_30 |
		target_30.getType().hasName("int")
		and target_30.getGreaterOperand().(PointerAddExpr).getType().hasName("unsigned char *")
		and target_30.getGreaterOperand().(PointerAddExpr).getLeftOperand().(VariableAccess).getTarget()=vp
		and target_30.getGreaterOperand().(PointerAddExpr).getRightOperand() instanceof Literal
		and target_30.getLesserOperand() instanceof PointerAddExpr
		and target_30.getEnclosingFunction() = func
		and target_30.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=val
		and target_30.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="50"
		and target_30.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ERR_put_error")
		and target_30.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(Literal).getValue()="20"
		and target_30.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="138"
		and target_30.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(Literal).getValue()="160"
		and target_30.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(StringLiteral).getValue()="s3_srvr.c"
		and target_30.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(4).(Literal).getValue()="1059")
}

predicate func_31(Variable val, Variable vcookie_len, Variable vp, Function func) {
	exists(GTExpr target_31 |
		target_31.getType().hasName("int")
		and target_31.getGreaterOperand().(PointerAddExpr).getType().hasName("unsigned char *")
		and target_31.getGreaterOperand().(PointerAddExpr).getLeftOperand().(VariableAccess).getTarget()=vp
		and target_31.getGreaterOperand().(PointerAddExpr).getRightOperand().(VariableAccess).getTarget()=vcookie_len
		and target_31.getLesserOperand() instanceof PointerAddExpr
		and target_31.getEnclosingFunction() = func
		and target_31.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=val
		and target_31.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="50"
		and target_31.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ERR_put_error")
		and target_31.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(Literal).getValue()="20"
		and target_31.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="138"
		and target_31.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(Literal).getValue()="160"
		and target_31.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(StringLiteral).getValue()="s3_srvr.c"
		and target_31.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(4).(Literal).getValue()="1066")
}

predicate func_32(Variable val, Variable vp, Function func) {
	exists(GTExpr target_32 |
		target_32.getType().hasName("int")
		and target_32.getGreaterOperand().(PointerAddExpr).getType().hasName("unsigned char *")
		and target_32.getGreaterOperand().(PointerAddExpr).getLeftOperand().(VariableAccess).getTarget()=vp
		and target_32.getGreaterOperand().(PointerAddExpr).getRightOperand() instanceof Literal
		and target_32.getLesserOperand() instanceof PointerAddExpr
		and target_32.getEnclosingFunction() = func
		and target_32.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=val
		and target_32.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="50"
		and target_32.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ERR_put_error")
		and target_32.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(Literal).getValue()="20"
		and target_32.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="138"
		and target_32.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(Literal).getValue()="160"
		and target_32.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(StringLiteral).getValue()="s3_srvr.c"
		and target_32.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(4).(Literal).getValue()="1136")
}

predicate func_33(Variable vi, Variable val, Variable vp, Function func) {
	exists(GTExpr target_33 |
		target_33.getType().hasName("int")
		and target_33.getGreaterOperand().(PointerAddExpr).getType().hasName("unsigned char *")
		and target_33.getGreaterOperand().(PointerAddExpr).getLeftOperand().(PointerAddExpr).getType().hasName("unsigned char *")
		and target_33.getGreaterOperand().(PointerAddExpr).getLeftOperand().(PointerAddExpr).getLeftOperand().(VariableAccess).getTarget()=vp
		and target_33.getGreaterOperand().(PointerAddExpr).getLeftOperand().(PointerAddExpr).getRightOperand().(VariableAccess).getTarget()=vi
		and target_33.getGreaterOperand().(PointerAddExpr).getRightOperand() instanceof Literal
		and target_33.getLesserOperand() instanceof PointerAddExpr
		and target_33.getEnclosingFunction() = func
		and target_33.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=val
		and target_33.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="50"
		and target_33.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ERR_put_error")
		and target_33.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(Literal).getValue()="20"
		and target_33.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="138"
		and target_33.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(Literal).getValue()="159"
		and target_33.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(StringLiteral).getValue()="s3_srvr.c"
		and target_33.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(4).(Literal).getValue()="1151")
}

predicate func_34(Variable vi, Variable val, Variable vp, Function func) {
	exists(GTExpr target_34 |
		target_34.getType().hasName("int")
		and target_34.getGreaterOperand().(PointerAddExpr).getType().hasName("unsigned char *")
		and target_34.getGreaterOperand().(PointerAddExpr).getLeftOperand().(VariableAccess).getTarget()=vp
		and target_34.getGreaterOperand().(PointerAddExpr).getRightOperand().(VariableAccess).getTarget()=vi
		and target_34.getLesserOperand() instanceof PointerAddExpr
		and target_34.getEnclosingFunction() = func
		and target_34.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=val
		and target_34.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="50"
		and target_34.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ERR_put_error")
		and target_34.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(Literal).getValue()="20"
		and target_34.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="138"
		and target_34.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(Literal).getValue()="159"
		and target_34.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(StringLiteral).getValue()="s3_srvr.c"
		and target_34.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(4).(Literal).getValue()="1217")
}

from Function func, Variable vi, Variable vj, Variable val, Variable vcookie_len, Variable vn, Variable vp, Variable vd, Variable vsession_length
where
not func_2(vj, val, vn, vp, vd)
and not func_3(val, vn, vp, vd)
and not func_4(val, vcookie_len, vn, vp, vd)
and not func_5(val, vn, vp, vd)
and not func_6(vi, val, vn, vp, vd)
and not func_7(vi, val, vn, vp, vd)
and func_16(func)
and func_24(func)
and func_29(vj, val, vp, func)
and func_30(val, vp, func)
and func_31(val, vcookie_len, vp, func)
and func_32(val, vp, func)
and func_33(vi, val, vp, func)
and func_34(vi, val, vp, func)
and vi.getType().hasName("int")
and vj.getType().hasName("int")
and val.getType().hasName("int")
and vcookie_len.getType().hasName("unsigned int")
and vn.getType().hasName("long")
and vp.getType().hasName("unsigned char *")
and vd.getType().hasName("unsigned char *")
and vsession_length.getType().hasName("unsigned int")
and vi.getParentScope+() = func
and vj.getParentScope+() = func
and val.getParentScope+() = func
and vcookie_len.getParentScope+() = func
and vn.getParentScope+() = func
and vp.getParentScope+() = func
and vd.getParentScope+() = func
and vsession_length.getParentScope+() = func
select func, vi, vj, val, vcookie_len, vn, vp, vd, vsession_length
