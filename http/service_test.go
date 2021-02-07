package http

import (
	"github.com/nodece/casbin-hraft-dispatcher/http/mocks"
	"testing"

	"github.com/golang/mock/gomock"
)

func TestHandler(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	store := mocks.NewMockStore(ctrl)
	store.EXPECT().Leader().Return(true, "127.0.0.1").AnyTimes()

	// TODO: move to integration test
	//ts := httptest.NewUnstartedServer(nil)
	//ts.EnableHTTP2 = true
	//ts.StartTLS()
	//defer ts.Close()
	//dispatcherBackend, err := NewDispatcherBackend(DefaultHttpAddress, ts.TLS, dispatcherStore)
	//assert.NoError(t, err)
	//go func() {
	//	err := dispatcherBackend.Start()
	//	assert.EqualError(t, err, http.ErrServerClosed.Error())
	//}()
	//defer func() {
	//	err := dispatcherBackend.Stop(context.Background())
	//	assert.NoError(t, err)
	//}()

	//commandHandler := http2.NewCommandHandler(dispatcherStore)
	//
	//c := &command.Command{Operation: command.AddOperation, Sec: "p", Ptype: "p", Rules: nil}
	//b, err := json.Marshal(c)
	//assert.NoError(t, err)
	//
	//dispatcherStore.EXPECT().Apply(b).Return(nil)
	//r := httptest.NewRequest(http.MethodPost, "/", bytes.NewBuffer(b))
	//w := httptest.NewRecorder()
	//commandHandler.ServeHTTP(w, r)
	//assert.Equal(t, http.StatusOK, w.Code)
	//
	//dispatcherStore.EXPECT().Apply(b).Return(errors.New("error"))
	//r = httptest.NewRequest(http.MethodPost, "/", bytes.NewBuffer(b))
	//w = httptest.NewRecorder()
	//commandHandler.ServeHTTP(w, r)
	//assert.Equal(t, http.StatusOK != w.Code, true)
}
